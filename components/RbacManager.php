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
	 * Ordered list of paths to search for policies
	 */
	public $policyPaths = [];
	
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
	 * Indicates if informative trace logging is enabled to see what permission
	 * checks are occuring for each request
	 */
	public $traceEnabled = false;
	
    public function init()
    {
        parent::init();
        
        // Add core config
        \Yii::configure($this, require __DIR__ . '/../config.php');
        
        // Add custom config if it exists
        $customConfig = \Yii::getAlias($this->rbacConfigFile);
        if (file_exists($customConfig)) {
        	\Yii::configure($this, require $customConfig);
        }
        
        // Inject the Rbac actions into all application controllers
		\Yii::$app->attachBehavior('rbac', [
			'class' => RbacFilter::className()
		]);
		
		\Yii::$container->set('yii\mongodb\Collection', 'mozzler\rbac\mongodb\Collection');
		\Yii::$container->set('yii\mongodb\ActiveQuery', 'mozzler\rbac\mongodb\ActiveQuery');

		$this->initRoles();

		$this->log('Initialised with roles: '.join(", ", $this->userRoles));
    }
    
    public function can($context, $operation, $params)
    {
	    if ($this->is('admin')) {
		    return true;
	    }
	    
	    $policies = $this->getPolicies($context, $operation, $params);

		return $this->processPolicies($policies, $params, get_class($context).':'.$operation);
    }
    
    // return true, false or a filter
    protected function processPolicies($policiesByRole, $params, $name) {
		if (sizeof($policiesByRole) == 0) {
			// Grant access as there are no policies to check
			$this->log('No valid policies found, granting full access for '.$name);
			return true;
		}
		
		// Loop through all policies granting access immediately or building
		// a list of filters
		$filters = [];
		foreach ($policiesByRole as $role => $rolePolicies) {
			foreach ($rolePolicies as $policyName => $policy) {
				// Skip the policy if it doesn't apply to any roles for this user
				if (!$this->is($role)) {
					$this->log("Skipping policy ($policyName) as it's for $role");
					continue;
				}
				
				// Policy grants full access
				if ($policy === true) {
					$this->log("Policy ($policyName) accepted, granting full access for $name");
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
						$this->log("Policy ($policyName) accepted, granting full access for $name");
						return true;
					} else if ($result === false) {
						// Policy doesn't apply, so skip
						$this->log("Policy ($policyName) doesn't apply, skipping");
						continue;
					} else if (is_array($result)) {
						$this->log("Policy ($policyName) has a filter");
						$filters[] = $result;
					} else {
						throw new InvalidArgumentException("Policy ($policyName) run() method returned an invalid response type");
					}
				}
			}
		}

		$filters = array_merge(['OR'], $filters);

		// If no filters found after processing policies, deny access
		// otherwise return the filters
		if (sizeof($filters) > 0) {
			$this->log("Applying filter to $name:\n".print_r($filters,true));
			return $filters;
		}
		
		$this->log("No policies matched, denying access for $name");
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
	
	public function canAccessModel($model, $operation) {
		return $this->can($model, $operation, [
			'model' => $model
		]);
	}
	
	public function canAccessCollection($collection, $operation) {
		if (!isset($this->collectionModels[$collection])) {
			throw new UnknownClassException("Unable to locate Model class associated with collection ($collection)");
		}
		
		$model = \Yii::createObject($this->collectionModels[$collection]);
		
		return $this->can($model, $operation, [
			'model' => $model
		]);
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
		// TODO
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
	
	protected function log($message) {
		if ($this->traceEnabled) {
			\Yii::trace('Rbac: '.$message, __METHOD__);
		}
	}
}

?>