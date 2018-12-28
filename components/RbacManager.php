<?php
namespace mozzler\rbac\components;

use Yii;
use yii\web\ErrorAction;
use mozzler\rbac\filters\RbacFilter;

/*use rappsio\engine\models\BaseModel;
use rappsio\engine\V8Tools;
use rappsio\engine\RappsioException;
use rappsio\engine\dpi\Base as dpiBase;*/

class RbacManager extends \yii\base\Component {
	
	public $rbacConfigFile = "config/rbac.php";
	public $policyPaths = [];
	public $roles = [];
	
    public function init()
    {
	    \Yii::trace('init()',__METHOD__);
        parent::init();
        
        // Add core config
        \Yii::configure($this, require __DIR__ . '/../config.php');
        
        // Add custom config
        $customConfig = '/../../' . $this->rbacConfigFile;
        if (file_exists($customConfig)) {
        	\Yii::configure($this, require $customConfig);
        }
        
        // Inject the Rbac actions into all application controllers
		\Yii::$app->attachBehavior('rbac', [
			'class' => RbacFilter::className()
		]);
    }
    
    public function canAccessAction($action) {
	    \Yii::trace('can access',__METHOD__);
		if ($action::className() == ErrorAction::className()) {
			return true;
		}
		
		return false;
	}
	
	//////

	private $_systemRoles;
	private $_userRoles;
	private $_requests;
	private $_cache;
	private $_policies;
	
	public $isAdmin = false;
	public $cacheEnabled = true;
	public $trace = false;
	public $logWarnings = false;
	
	/*public function __construct() {
		$this->_requests = [];
		$this->_cache = [];
		$this->_policies = [];
	}*/
	
	public function is($user, $role) {
		return in_array($role, $this->getRoles($user));
	}
	
	/**
	 * establish if a user can perform a specific operation
	 * see getAccessFilter for rules that applie if a filter
	 * is found
	 */
	public function can($user, $operation, $params) {
		return $this->getAccessFilter($user, $operation, $params);
	}

	/**
	 * if result is true, then unconditional access is granted
	 *  if result is false then permission denied
	 *	if result is an array that indicates a conditional filter
	 *	applies so a user can not automatically perform the operation
	 *
	 * if $params specifies a model_id, and a filter applies,
	 * the model_id will attempt to be retreived using the filter.
	 * if a result is found, true will be returned, otherwise false
	 */
	public function getAccessFilter($user, $operation, $params) {
		if ($this->isAdmin)
			return true;
			
		$resourceName = $this->buildResourceName($params);
		
		if (isset($params['model'])) {
			// always grant list and view access to application data
			if ($operation == 'list' || $operation == 'view') {
				if (preg_match("/^app\\./", $resourceName)) {
					return true;
				}
			}
			
			// Always grant access to read / write to the cache. ideally would force
			// rappsio\cache\Cache to ignore permissions, but that requires re-writing core
			// yii caching object. At this point, I can't think of any situation where
			// access to the cache object would be denied. End users don't have access
			// and any restrictions on packages only setting their own cache would need
			// to be implemented closer to the Rappsio global
			if (substr($resourceName,0,9) == "app.cache") {
				return true;
			}
			
			if (!is_object($params['model']))
				$params['model'] = \Yii::$app->rappsiomodel->getModel($params['model']);
		}
		
		if ($this->trace)
			Yii::trace("Applying permission filters for $resourceName ($operation)", __METHOD__);

		$request = $resourceName.'_'.$operation;
		if (in_array($request, $this->_requests))
			throw new RappsioException("Recursive loop found in access filter for $resourceName ($operation)");
		
		$this->_requests[] = $request;
		
		$userRoles = $this->getRoles($user);
		
		// always give administrator role full access
		if (in_array("Administrator", $userRoles)) {
			array_pop($this->_requests);
			if ($this->trace)
				Yii::trace("Automatically granting administrator access", __METHOD__);
			return true;
		}
		
		$cacheKey = $this->getCacheKey($operation, $resourceName, isset($params['model']) ? $params['model'] : null);
		if (isset($params["model_id"]))
			$cacheKey['model_id'] = $params["model_id"];
		
		$imCacheKey = md5(json_encode($cacheKey));

		if (isset($this->_cache[$imCacheKey])) {
			if ($this->trace) {
				\Yii::trace("Returning permissions from in-memory cache");
			}
			
			//return $this->_cache[$imCacheKey];
		}
		
		$policies = $this->getPolicies($operation, $resourceName, isset($params['model']) ? $params['model'] : null);
		
		// grant access (eg: don't restric access if no valid policies)
		if (sizeof($policies) == 0) {
			if ($this->trace)
				Yii::trace("Granting access as no policies found", __METHOD__);
			array_pop($this->_requests);
			return true;
		}
		
		if ($this->trace)
			Yii::trace("Processing ".sizeof($policies)." policies", __METHOD__);

		$filter = [];
		foreach ($policies as $policy) {	
			if ($this->trace)
				Yii::trace("Processing ".$policy['name'], __METHOD__);
			$policyRoles = $policy['policy_roles'];
			
			// user automatically fails the rule if not in the role list
			if (sizeof(array_intersect($policyRoles, $userRoles)) == 0) {
				if ($this->trace)
					Yii::trace("Failed policy ".$policy['name'], __METHOD__);
				continue;
			}
		
			// automatically grant access if policy is set to grant
			// or has no rules
			if ($policy['policy_type'] == "grant" || !$policy['rules']) {
				if ($this->trace)
					Yii::trace("Granting access via policy ".$policy['name'], __METHOD__);
				array_pop($this->_requests);
				return true;
			}
			
			$rules = $this->buildRules($policy['rules'], $policy['name']);

			if ($rules)
				$filter[] = $rules;
		}
		
		// user has not passed any policies and has no filters
		// so automatically fail the rule
		if (sizeof($filter) == 0) {
			if ($this->logWarnings)
				Yii::warning("User failed all policies accessing $resourceName ($operation)", __METHOD__);
			array_pop($this->_requests);
			$this->_cache[$imCacheKey] = false;
			return false;
		}
		
		if ($this->trace)
			Yii::trace("Applying ".sizeof($filter)." filters to the query", __METHOD__);
		
		$filter = array_merge(['OR'], $filter);
		
		if ($this->trace)
			Yii::trace("Applying filter: ".print_r($filter,true));
		
		array_pop($this->_requests);
		
		if (isset($params["model_id"]) && isset($params["model"])) {
			if ($this->trace)
				Yii::trace("Have a specific model, so apply filter to establish if permission is granted");
			// we have a specific model being requested, so need to
			// perform a query with the filter to establish if permission
			// is granted
			$namespace = $params["model"]->modelNamespace();
			
			$query = $params["model"]->find();
			$query->andWhere($filter);
			$query->andWhere([
				"_id" => $params["model_id"]
			]);
			
			$query->checkPermissions = false;
			$results = $query->one();
			
			if (sizeof($results) == 1) {
				// found the model with the security filter applied so
				// user has permission to access
				$this->_cache[$imCacheKey] = true;
				return true;
			}
			
			// didn't find the model with the security model appied
			// so the user can not access
			$this->_cache[$imCacheKey] = false;
			return false;
		}
		
		// user can pass any of the filters
		$this->_cache[$imCacheKey] = $filter;
		return $filter;
	}
	
	// get an array of all the valid roles for a user, including child roles
	private function getRoles($user) {
		// return user roles from cache if set
		if (isset($this->_userRoles))
			return $this->_userRoles;
	
		// auto-assign "Public" role to users
		if (!$user)
			return ['Public'];

		$systemRoles = $this->getSystemRoles();
		$userRoles = $user->getRoles();
		
		$allRoles = $userRoles;
		foreach ($userRoles as $roleName) {
			foreach ($systemRoles[$roleName] as $childRole) {
				if (!in_array($childRole, $allRoles)) 
					$allRoles[] = $childRole;
			}
		}
		
		$this->_userRoles = $allRoles;
		
		return $allRoles;
	}
	
	private function getCacheKey($operation, $resource, $model=null) {
		$resourceNames = [$resource];
		
		if ($model) {
			// load resource names based on model heirarchy
			// 'resource' => 'rappsio.auth.user/1a3fad27327f229:first_name' (full model example)
			$parts = preg_split("/\\//", $resource);
			$resourceDetail = "";
			if (sizeof($parts) > 1)
				$resourceDetail = $parts[1];
	
			$parentTypes = $model->getParentTypes();
			foreach ($parentTypes as $parentModelType)
				$resourceNames[] = $parentModelType.$resourceDetail;
		}
		
		$cacheKey = [
			'operation' => $operation,
			'resource_name' => $resourceNames
		];
		
		return $cacheKey;
	}
	
	// get all valid policies for the given request
	private function getPolicies($operation, $resource, $model=null) {
		$cacheKey = $this->getCacheKey($operation, $resource, $model);
		
		$filter = $cacheKey;
		$filter['status'] = 'active';
		
		// check in memory cache for policies
		$imCacheKey = md5(json_encode($cacheKey));
		if (isset($this->_policies[$imCacheKey])) {
			if ($this->trace)
				\Yii::trace("Policies loaded from in-memory cache");
			return $this->_policies[$imCacheKey];
		}
		
		// check application cache for policies
		if ($this->cacheEnabled) {
			$cacheKey['type'] = 'policies';
			$policies = \Yii::$app->cache->get("rappsio.auth/policies", $cacheKey);
			// TODO: compare the expiry date
			if ($policies) {
				// save policies into in memory cache
				$this->_policies[$imCacheKey] = $policies;
				return $policies;
			}
		}
		
		$results = \Yii::$app->rappsiomodel->getModel("rappsio.auth.policy")->find(false)->where($filter)->all();

		// remove any policies that should not be inherited
		$policies = [];
		if ($model)
			$parentTypes = $model->getParentTypes();
		else
			$parentTypes = [];
		
		foreach ($results as $policy) {
			if ($policy->no_inherit && in_array($policy->resource_name, $parentTypes)) {
				continue;
			}
			
			// convert policies to an array and load all the roles for each policy
			// this ensures serialization happens nicely when caching
			$arrayPolicy = $policy->toArray();
			$arrayPolicy['policy_roles'] = $this->getPolicyRoles($policy);
			
			$policies[] = $arrayPolicy;
		}
		
		// cache policies
		if ($this->cacheEnabled) {
			\Yii::$app->cache->set("rappsio.auth/policies", $cacheKey, $policies);
		}
		
		// save policies into in memory cache
		$this->_policies[$imCacheKey] = $policies;
		
		return $policies;
	}
	
	// take JS rules, v8ify and create mongo filter
	private function buildRules($rules, $policyName) {
		return V8Tools::jsonToArray($rules, "Policy rule ".$policyName);
	}
	
	/**
	 * Takes a map like follows (from database):
	 * [
	 *  Worker: []
	 *	Developer: [Worker, Designer],
	 *	Designer: [Worker],
	 *	Manager: [Developer]
	 * ],
	 * and creates a map like this:
	 * [
	 *	Worker: [],
	 *	Developer: [Worker, Designer],
	 *	Designer: [Worker],
	 *	Manager: [Developer, Designer, Worker]
	 * ],
	 */
	private function getSystemRoles() {
		// try loading from local cache
		if (isset($this->_systemRoles))
			return $this->_systemRoles;
		
		// try loading from mongo cache
		if ($this->cacheEnabled) {
			$this->_systemRoles = \Yii::$app->cache->get("rappsio.auth", "systemRoles");
			if ($this->_systemRoles) {
				return $this->_systemRoles;
			}
		}

		$systemRoles = \Yii::$app->rappsiomodel->getModel("rappsio.auth.role")->find(false)->all();
		
		// build lookup table
		$roleObjects = [];
		foreach ($systemRoles as $role) {
			$roleObjects[$role->name] = $role;
		}
		
		$roles = [];
		foreach ($roleObjects as $roleName => $role) {
			$roles[$role->name] = [];
			$relatedRoles = $role->getRelated("child_roles", [], false, null, [], ["name"], false);
			foreach ($relatedRoles as $childRole) {
				$roles[$role->name][] = $childRole->name;
			}
		}
		
		// build the final roles array
		$finalRoles = [];
		foreach ($roles as $roleName => $childRoles) {
			$finalRoles[$roleName] = $this->recursiveSystemRoles($roleName, $roles);
		}
		
		$this->_systemRoles = $finalRoles;
		
		if ($this->cacheEnabled) {
			$systemRoles = \Yii::$app->cache->set("rappsio.auth", "systemRoles", $this->_systemRoles);
		}
		
		return $finalRoles;
	}
	
	/**
	 * @param 
	 */
	private function recursiveSystemRoles($roleName, $allRoles) {
		// roleName = Manager
		// result = [Developer, Designer, Worker]
		$result = $allRoles[$roleName];
		
		foreach ($allRoles[$roleName] as $role) {
			// role = Developer
			$childRoles = $this->recursiveSystemRoles($role, $allRoles);
			foreach ($childRoles as $childRole)
				if (!in_array($childRole, $result))
					$result[] = $childRole;
		}
		
		return $result;
	}
	
	// TODO: Is this the best way to store and recover roles?
	// need to do by name to support cross package policy definitions
	private function getPolicyRoles($policy) {
		$roles = [];
		foreach ($policy->getRelated("roles", [], false, null, [], ["name"], false) as $role) {
			$roles[] = $role->name;
		}
		
		return $roles;
	}
	
	/**
	 * Build the security resource name for a given set of parameters
	 *
	 * $params = [
	 *		'model' => BaseModel instance or string
	 *		'field' => 'first_name'
	 *		'resource' => 'rappsio.auth.user/first_name' (model and field example)
	 *		'resource' => 'rappsio.application' (action example)
	 *	];
	 */
	private function buildResourceName($params) {
		if (isset($params['resource']))
			return $params['resource'];
		
		$resource = "";
		if (isset($params['model'])) {
			$resource = (string)$params['model'];

			if (isset($params['field'])) {
				$resource .= "/".$params['field'];
			}
		}
		
		return $resource;
	}
}

?>