<?php
namespace mozzler\rbac\components;

use Yii;
use yii\web\ErrorAction;
use mozzler\rbac\filters\RbacFilter;
use yii\helpers\ArrayHelper;
use mozzler\base\helpers\ControllerHelper;

use yii\base\InvalidArgumentException;
use yii\base\UnknownClassException;

class RbacManager extends \yii\base\Component {

	/**
	 * Location of any custom configuration file
	 */
	public $rbacConfigFile = "@app/config/rbac.php";

	/**
	 * List of all available roles
     *
     * This will be filled with data from the DB such as:
      [
        'public' => [ 'name' => 'Public'],
        'admin' => ['name' => 'Administrator'],
        'registered' => ['name' => 'Registered User']
      ]
	 */
	public $roles = [];

	/**
	 * Name of the admin role that gives unrestricted access
	 */
	public $adminRole = 'admin';

	/**
	 * List of roles a registered user is automatically granted
	 */
	public $registeredUserRoles = ['registered'];

	/**
	 * List of custom policies to apply beyond those embbedded in `rbac()` methods.
	 * These custom policies will take precedence.
	 */
	public $policies = [];

	/**
	 * Default roles to apply to all users
	 */
	public $defaultUserRoles = ['public'];

	/**
	 * Roles that are hidden.
	 * 
	 * By default, hide `public` and `registered` as they are used internally
	 * to distguish between logged in and non-logged in users
	 */
	public $hiddenUserRoles = ['public', 'registered'];

	/**
	 * Roles of the current logged in user
	 */
	private $userRoles = [];

	/**
	 * Mapping of collections to models
	 */
	private $collectionModels = [];

	/**
	 * List of collections that should not have permissions checked
	 */
	public $ignoredCollections = [];

	/**
	 * Indicates if informative trace logging is enabled to see what permission
	 * checks are occuring for each request
	 */
	public $traceEnabled = false;

	/**
	 * 1 = Normal
	 * 2 = Extra verbose
	 */
	public $traceLevel = 1;

	/**
	 * Boolean indicating if the RBAC manager is active. Internally this is
	 * set once Yii2 application is initialised (App::EVENT_BEFORE_REQUEST)
	 */
	private $isActive = false;

	/**
	 * Force the system to be in admin mode, which effectively disables all
	 * permission checks
	 */
	public $forceAdmin = false;

    public function init()
    {
        parent::init();

        // Add core config
        $config = require __DIR__ . '/../config.php';

        // Add custom config if it exists
        $customConfig = \Yii::getAlias($this->rbacConfigFile);
        if (file_exists($customConfig)) {
	        $config = ArrayHelper::merge($config, require $customConfig);
        }

        \Yii::configure($this, $config);

        $this->userRoles = $this->defaultUserRoles;

		\Yii::$container->set('yii\mongodb\Collection', 'mozzler\rbac\mongodb\Collection');
		\Yii::$container->set('yii\mongodb\ActiveQuery', 'mozzler\rbac\mongodb\ActiveQuery');

		// User may not exist (ie: In a console application)
		if (\Yii::$app->has('user')) {
			\Yii::$app->user->on(\yii\web\User::EVENT_AFTER_LOGIN, [$this, "initRoles"]);
			$this->initRoles();
		}
    }

	/**
	 * @param $context 		Action or Model instance
	 * @param $operation	ie: find, update, delete
	 * @param $params		ie: ['model' => $model]
	 */
    public function can($context, $operation, $params)
    {
	    if (!$this->isActive) {
		    $this->setActive();
		}
		
		if ($this->forceAdmin) {	
		    return true;	
		}
		
		$checkName = get_class($context).':'.$operation;
		$this->log("Checking permission request for $checkName", __METHOD__);

		$policies = $this->getRolePolicies($context, $operation, $params);
		$this->log("Processing policies for operation $operation: ".print_r($policies,true), __METHOD__,true);

		return $this->processPolicies($policies, $params, $checkName);
    }

    // return true, false or a filter
    protected function processPolicies($policiesByRole, $params, $name) {
		if (sizeof($policiesByRole) == 0) {
			// Grant access as there are no policies to check
			$this->log('No valid policies found, granting full access for '.$name,__METHOD__);
			return true;
		}

		// Loop through all policies granting access immediately or building
		// a list of filters
		$filters = [];
		foreach ($policiesByRole as $role => $rolePolicies) {
			foreach ($rolePolicies as $policyName => $policy) {
				// Skip the policy if it doesn't apply to any roles for this user
				if (!$this->is($role)) {
					$this->log("Skipping policy ($policyName) as it's for $role",__METHOD__,true);
					continue;
				}

				// Policy grants full access
				if ($policy === true) {
					$this->log("Policy ($policyName) accepted, granting full access for $name",__METHOD__);
					return true;
				}

				// Policy is false, so skip
				if ($policy === false) {
					continue;
				}

				$policy = \Yii::createObject($policy);

				if ($policy instanceof \mozzler\rbac\policies\BasePolicy) {
					$result = $policy->run($params);
					if ($result === true) {
						// Grant full access
						$this->log("Policy ($policyName) accepted, granting full access for $name",__METHOD__);
						return true;
					} else if ($result === false) {
						// Policy doesn't apply, so skip
						$this->log("Policy ($policyName) doesn't apply, skipping",__METHOD__,true);
						continue;
					} else if (is_array($result)) {
						$this->log("Policy ($policyName) has a filter",__METHOD__);
						$filters[] = $result;
					} else {
						throw new InvalidArgumentException("Policy ($policyName) run() method returned an invalid response type",__METHOD__);
					}
				}
			}
		}

		// If filters exist, join them with an "OR" query
		if (sizeof($filters) > 0) {
			$this->log("Applying filter to $name:\n".print_r($filters,true),__METHOD__);
			$filters = array_merge(['OR'], $filters);

			if (isset($params["_id"]) && isset($params["model"])) {
				$this->log("Have a specific model, so attempting to fetch with Rbac filter to establish if permission is granted", __METHOD__,true);

				// A specific model is being requested, so need to perform a query with the filter
				// to establish if permission is granted
				$model = $params['model'];

				$query = $model->find();
				$query->andWhere($filters);
				$query->andWhere([
					'_id' => $params['_id']
				]);

				$query->checkPermissions = false;
				$results = $query->one();

				if ($results) {
					// Found the model with the security filter applied so the user has permission to access
					$this->log('Model '.$params['_id'].' was found, permission granted', __METHOD__);
					return true;
				}

				// Didn't find the model with the security model appied so the user can not access
				$this->log('Model '.$params['_id'].' was not found, permission denied', __METHOD__);
				return false;
			}

			return $filters;
		}

		// No filters exist, but policies existed, so deny access
		$this->log("No policies matched, denying access for $name",__METHOD__);
		return false;
	}

	/**
	 * Check if the currently logged in user can access a specific
	 * action on a controller linked to a model.
	 *
	 * @param	$controller	mixed	Instance of `yii\base\Controller` or a string representing the full class name of a controller
	 * @param	$action	string		String representation of the action (ie: `index`)
	 * @return	boolean				True if the current user can access the action on the controller
	 */
	public function canAccessControllerAction($controller, $actionName) {
		// Convert controller to a proper Controller object if it's a string
		if (is_string($controller)) {
			$controllerObj = ControllerHelper::buildController($controller);

			// Unable to create a class for the given controller object
			if (!$controllerObj) {
				throw new \yii\base\UnknownPropertyException('Unable to locate requested controller ('.$controller.') when checking permissions');
			}

			$controller = $controllerObj;
		}

		$action = $controller->createAction($actionName);

		if (!$action) {
			throw new \yii\base\UnknownPropertyException('Unable to locate requested action ('.$actionName.') when checking permissions');
		}

		return $this->canAccessAction($action);
	}

    public function canAccessAction($action) {
		if ($action::className() == ErrorAction::className()) {
			return true;
		}

		return $this->can($action->controller, $action->id, [
			'action' => $action
		]);
	}

	public function canAccessCollection($collection, $operation, $metadata=[]) {
		// Check if the collection should not have RBAC applied
		if (in_array($collection, $this->ignoredCollections)) {
			$this->log("Collection ({$collection}) is ignored, granting access for operation: $operation", __METHOD__);
			return true;
		}

		if (!isset($this->collectionModels[$collection])) {
            // If you get this error, especially with codeception tests try running createObject on the model first. E.g: `\Yii::createObject('mozzler\auth\models\oauth\OAuthClientModel');`
		    // If you are using codeception for testing and are adding fixtures then get this error, try running it with `\Yii::$app->rbac->forceAdmin = true;`
            // If it's something you want to ignore complete then try adding it to the ignoreCollection list. E.g `\Yii::$app->rbac->ignoreCollection('mozzler.auth.refresh_tokens')`
			throw new UnknownClassException("Unable to locate Model class associated with collection ($collection)");
		}

		$model = \Yii::createObject($this->collectionModels[$collection]);
		$metadata['model'] = $model;

		return $this->can($model, $operation, $metadata);
	}

	public function canAccessModel($model, $operation, $metadata=[]) {
		$result = $this->can($model, $operation, $metadata);

		if ($result === true) {
			return true;
		} elseif ($result === false) {
			return false;
		}
		else {
			/**
			 * We have a database filter that determines if the user can access this model.
			 *
			 * Run the query trying to find the model.
			 */
			$query = $model->find();
			$query->andWhere($result);
			$query->andWhere([
				"_id" => $model->id
			]);

			$query->checkPermissions = false;
			$queryCount = $query->count();

			if ($queryCount >= 1) {
				// found the model with the security filter applied so
				// user has permission to access
				return true;
			}

			// didn't find the model with the security model appied
			// so the user can not access
			return false;
		}
	}

	/**
	 * Check if the current user belongs to the given role
	 */
	public function is($role) {
		return in_array($role, $this->userRoles);
	}

	/**
	 * Determine the roles available for this user
	 */
	protected function initRoles() {
		if (!\Yii::$app->has('user')) {
			return;
		}

		$user = \Yii::$app->user->getIdentity();

		if ($user) {
			$this->log("Found user ".$user->id." with roles: ".join(", ",$this->getUserRoles($user)), __METHOD__,true);

			// Initialise roles with defaults plus registered user roles
			$this->userRoles = array_merge($this->defaultUserRoles, $this->registeredUserRoles);

			// Add this user's custom roles
			$this->userRoles = array_merge($this->userRoles, $this->getUserRoles($user));

			$this->log('Initialised with user roles: '.join(", ", $this->userRoles),__METHOD__,true);
		}
	}

	/**
	 * Get all the roles linked to this user
	 */
	protected function getUserRoles($user)
	{
		if (is_array($user->roles)) {
			return $user->roles;
		}

		return [];
	}

    protected function getPolicies($context) {
        $foundConfigs = [];

        // -- Have removed the RBAC Object Inheritance checks that this used to do in v1.0
        // Instead you can use `return ArrayHelper::merge(parent::rbac(), [ ... Custom RBAC checks here ... ]` in your RBAC model method
        $className = get_class($context);
        // Load RBAC configuration for this controller
        if (method_exists($className, 'rbac')) {
            $rbac = $className::rbac();
            $foundConfigs[$className] = $rbac;
        }
        // Load RBAC custom configuration for defined for this controller
        foreach ($this->policies as $role => $rolePolicies) {
            // Locate any policies for this class
            if (isset($rolePolicies[$className])) {
                $foundConfigs[$className] = ArrayHelper::merge(isset($foundConfigs[$className]) ? $foundConfigs[$className] : [], [
                    $role => $rolePolicies[$className]
                ]);
            }
        }
        return $foundConfigs;
    }

	protected function getRolePolicies($context, $operation, $params) {
		$foundConfigs = $this->getPolicies($context);
		$this->log('Found policies:', __METHOD__,true);
		$this->log(print_r($foundConfigs,true), __METHOD__,true);

		// Merge all the policies in the correct order
		$foundConfigs = array_reverse($foundConfigs);

		$policiesByRole = [];
		foreach ($foundConfigs as $className => $config) {
			foreach ($config as $role => $rolePolicies)  {
				if (!isset($rolePolicies[$operation])) {
					// no policies for the requested operation, so skip
					continue;
				}

				$policies = $rolePolicies[$operation];

				if (!isset($policiesByRole[$role])) {
					$policiesByRole[$role] = [];
				}

				if (!is_array($policies)) {
					$policies = [
						'default' => $policies
					];
				}

				$policiesByRole[$role] = ArrayHelper::merge($policiesByRole[$role], $policies);
			}
		}

		return $policiesByRole;
	}

	public function registerModel($collectionName, $className) {
		$this->collectionModels[$collectionName] = $className;
	}

	protected function log($message, $meta, $verbose=false) {
		if ($this->traceEnabled) {
			if ($verbose && $this->traceLevel != 2) {
				return;
			}

			\Yii::trace('Rbac: '.$message, $meta);
			// TODO: Detect if in unit test environment
			//\Codeception\Util\Debug::debug($message);
		}
	}

	/**
	 * Get a list of key/value list of options
	 */
	public function getRoleOptions($includeHidden=false) {
		$options = [];
		foreach ($this->roles as $roleName => $role) {
			$options[$roleName] = $role['name'];
		}

		if (!$includeHidden) {
			foreach ($this->hiddenUserRoles as $role) {
				unset($options[$role]);
			}
		}

		return $options;
	}

	public function setActive() {
		$this->isActive = true;
		$this->initRoles();
	}

	public function ignoreCollection($collectionName) {
		if (!in_array($collectionName, $this->ignoredCollections)) {
			$this->log("Ignoring permission checks on $collectionName", __METHOD__);
			$this->ignoredCollections[] = $collectionName;
		}
	}

    /**
     * @param $collectionName
     *
     * Remove the collectionName from the ignored collections array.
     * This is mainly used by the codeception tests
     *
     * Example datastructure $this->ignoredCollections = Array
     * (
     * [0] => app.session
     * [1] => viterra.deviceFavourite
     * )
     *
     * \Yii::$app->rbac->dontIgnoreCollection('viterra.deviceFavourite')
     */
    public function dontIgnoreCollection($collectionName)
    {
        if (in_array($collectionName, $this->ignoredCollections)) {
            $this->log("Adding back permission checks on $collectionName", __METHOD__);
            unset($this->ignoredCollections[array_search($collectionName, $this->ignoredCollections)]);
        }
    }
}

?>
