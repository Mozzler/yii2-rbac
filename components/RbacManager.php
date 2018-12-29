<?php
namespace mozzler\rbac\components;

use Yii;
use yii\web\ErrorAction;
use mozzler\rbac\filters\RbacFilter;
use yii\base\InvalidArgumentException;
use yii\helpers\ArrayHelper;

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

		$this->initRoles();

		\Yii::trace('RBAC initialised with roles: '.join(", ", $this->userRoles), __METHOD__);
    }
    
    public function can($context, $operation, $params)
    {
	    if ($this->is('admin')) {
		    return true;
	    }
	    
	    if ($context instanceof \yii\base\Controller) {
		    $policies = $this->getActionPolicies($context, $operation, $params);
	    } else if ($context instanceof \yii\base\Model) {
		    $policies = $this->getModelPolicies($context, $operation, $params);
		} else {
			$policies = [];
		}
		
		return $this->processPolicies($policies, $params);
    }
    
    // return true, false or a filter
    protected function processPolicies($policies, $params) {
	    \Yii::trace('Have '.sizeof($policies).' policies to process',__METHOD__);

		if (sizeof($policies) == 0) {
			// Grant access as there are no policies to check
			\Yii::trace('No valid policies found, granting full access', __METHOD__);
			return true;
		}
		
		// Loop through all policies granting access immediately or building
		// a list of filters
		$filters = [];
		foreach ($policies as $policyId => $policyDefinition) {
			$role = $policyDefinition['role'];
			$policy = $policyDefinition['policy'];
			
			// Skip the policy if it doesn't apply to any roles for this user
			if (!$this->is($role)) {
				continue;
			}
			
			// Policy grants full access
			if ($policy === true) {
				return true;
			}
			
			$policy = \Yii::createObject($policy);
			
			if ($policy instanceof \mozzler\rbac\policies\BasePolicy) {
				$result = $policy->run();
				if ($result === true) {
					// Grant full access
					return true;
				} else if ($result === false) {
					// Policy doesn't apply, so skip
					continue;
				} else if (is_array($result)) {
					$filters[] = $result;
				} else {
					throw new InvalidArgumentException("Policy run() method returned an invalid response type");
				}
			}
		}

		// If no filters found after processing policies, deny access
		// Otherwise return the filters
		return sizeof($filters) == 0 ? false : $filters;
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
		$user = \Yii::$app->user->identity;
		
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
	
	protected function getActionPolicies($controller, $actionId, $params) {
		$action = $params['action'];
		
		$rbacConfig = [];
		$classes = array_merge([get_class($controller)], class_parents($controller));
		foreach ($classes as $className) {
			// Load RBAC configuration for this controller
			if (method_exists($className, 'rbac')) {
				$rbac = $className::rbac();	
				$rbacConfig = ArrayHelper::merge($rbacConfig, $rbac);
			}
			
			// Load RBAC custom configuration for defined for this controller
			foreach ($this->policies as $role => $rolePolicies) {
				// Locate any policies for this class
				if (isset($rolePolicies[$className])) {
					// Merge the found policies, wrapping in the correct role
					$rbacConfig = ArrayHelper::merge($rbacConfig, [
						$role => $rolePolicies[$className]
					]);
				}
			}
			
			if ($className == 'yii\base\Controller') {
				break;
			}
		}
		
		// Create a flat array of policy definitions combining the policy with it's role
		$policies = [];
		foreach ($rbacConfig as $role => $rolePolicies) {
			if (isset($rolePolicies[$actionId])) {
				foreach ($rolePolicies[$actionId] as $actionPolicyId => $policy) {
					$policies[] = [
						'role' => $role,
						'policy' => $policy
					];
				}
			}
		}
		
		return $policies;
	}
	
	protected function getModelPolicies($model, $operation, $params) {
		$policies = [];
		
		return $policies;
	}
}

?>