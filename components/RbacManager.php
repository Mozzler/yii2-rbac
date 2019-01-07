<?php
namespace mozzler\rbac\components;

use Yii;
use yii\web\ErrorAction;
use mozzler\rbac\filters\RbacFilter;
use yii\helpers\ArrayHelper;

use yii\base\InvalidArgumentException;
use yii\base\UnknownClassException;

class RbacManager extends \yii\base\Component {
	
	/**
	 * Location of any custom configuration file
	 */
	public $rbacConfigFile = "@app/config/rbac.php";
	
	/**
	 * List of all available roles
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
	 * Roles of the current logged in user. Any default
	 * values will be applied to all users.
	 */
	private $userRoles = ['public'];
	
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
		
		\Yii::$container->set('yii\mongodb\Collection', 'mozzler\rbac\mongodb\Collection');
		\Yii::$container->set('yii\mongodb\ActiveQuery', 'mozzler\rbac\mongodb\ActiveQuery');
    }
    
    public function can($context, $operation, $params)
    {
	    if (!$this->isActive) {
		    $this->setActive();
	    }
	    
	    if ($this->is('admin') || $this->forceAdmin) {
		    return true;
	    }
	    
	    $policies = $this->getPolicies($context, $operation, $params);

		return $this->processPolicies($policies, $params, get_class($context).':'.$operation);
    }
    
    // return true, false or a filter
    protected function processPolicies($policiesByRole, $params, $name) {
	    $this->log("Checking permission request for $name",__METHOD__);
	    
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
					$this->log("Skipping policy ($policyName) as it's for $role",__METHOD__);
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
					$result = $policy->run();
					if ($result === true) {
						// Grant full access
						$this->log("Policy ($policyName) accepted, granting full access for $name",__METHOD__);
						return true;
					} else if ($result === false) {
						// Policy doesn't apply, so skip
						$this->log("Policy ($policyName) doesn't apply, skipping",__METHOD__);
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
				$this->log("Have a specific model, so attempting to fetch with Rbac filter to establish if permission is granted", __METHOD__);
	
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
		if (!isset($metadata['model'])) {
			$metadata['model'] = $model;
		}
		
		return $this->can($model, $operation, $metadata);
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
		$user = \Yii::$app->user->getIdentity();

		if ($user) {
			$this->log("Found user ".$user->id." with roles: ".join($this->getUserRoles($user),", "), __METHOD__);
			// Add registered user roles
			$this->userRoles = array_merge($this->userRoles, $this->registeredUserRoles);
			
			// Add this user's custom roles
			$this->userRoles = array_merge($this->userRoles, $this->getUserRoles($user));
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
	
	protected function getPolicies($context, $operation, $params) {
		$foundConfigs = [];
		
		$classes = array_merge([get_class($context)], class_parents($context));
		foreach ($classes as $className) {
			// Load RBAC configuration for this controller
			if (method_exists($className, 'rbac')) {
				$rbac = $className::rbac();
				$foundConfigs[$className] = $rbac;
			}
			
			// Load RBAC custom configuration for defined for this controller
			foreach ($this->policies as $role => $rolePolicies) {
				// Locate any policies for this class
				if (isset($rolePolicies[$className])) {
					$foundConfigs[$className] = [
						$role => $rolePolicies[$className]
					];
				}
			}
			
			if ($className == 'yii\base\Controller' || $className == 'yii\base\Model') {
				break;
			}
		}
		
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
	
	protected function log($message, $meta) {
		if ($this->traceEnabled) {
			\Yii::trace('Rbac: '.$message, $meta);
		}
	}
	
	/**
	 * Get a list of key/value list of options
	 */
	public function getRoleOptions($excludeDefaults=true) {
		$options = [];
		foreach ($this->roles as $roleName => $role) {
			$options[$roleName] = $role['name'];
		}
		
		if ($excludeDefaults) {
			unset($options['public']);
			unset($options['registered']);
		}
		
		return $options;
	}
	
	public function setActive() {
		$this->isActive = true;
		$this->initRoles();
		$this->log('Initialised with user roles: '.join(", ", $this->userRoles),__METHOD__);
	}
	
	public function ignoreCollection($collectionName) {
		if (!in_array($collectionName, $this->ignoredCollections)) {
			$this->log("Ignoring permission checks on $collectionName", __METHOD__);
			$this->ignoredCollections[] = $collectionName;
		}
	}
}

?>