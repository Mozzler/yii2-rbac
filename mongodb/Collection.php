<?php
namespace mozzler\rbac\mongodb;

use yii\mongodb\Collection as BaseCollection;
use mozzler\rbac\PermissionDeniedException;

/**
 * Custom Collection class that adds `checkPermission` and
 * `rbacOperation` support to MongoDB Collection
 */
class Collection extends BaseCollection {
	
	public $checkPermissions = true;
	public $rbacOperation;
	
	// -- PHP 8.3 / yii2-mongodb 3.0+: Added $execOptions parameter
	public function find($condition=[], $fields=[], $options=[], $execOptions=[]) {
		$condition = $this->buildPermissionFilter('find', $condition);

		if ($condition === false) {
			// No permission, so generate a query that will always return nothing
			return parent::find(['_id' => '-0'], $fields, $options, $execOptions);
		}

		return parent::find($condition, $fields, $options, $execOptions);
	}
	
	protected function buildPermissionFilter($operation, $condition=[]) {
		if (!$this->checkPermissions) {
			return $condition;
		}
		
		$filter = \Yii::$app->rbac->canAccessCollection($this->name, $operation);

		if ($filter === true) {
			// full access permitted, so don't apply any filtering
			return $condition;
		} else if ($filter === false) {
			return false;
		} else if ($filter) {
			// apply the filter as an AND on the query
			if (sizeof($condition) == 0) {
				$condition = $filter;
			}
			else {
				$condition = array_merge(['AND'], [$condition, $filter]);
			}
		}
		
		return $condition;
	}
	
	// -- PHP 8.3 / yii2-mongodb 3.0+: Added $execOptions parameter, removed $throwException
	public function insert($data, $options = [], $execOptions = []) {
    	$this->checkPermissions("insert");
    	
		return parent::insert($data, $options, $execOptions);
    }
    
    // -- PHP 8.3 / yii2-mongodb 3.0+: Added $execOptions parameter, removed $throwException
    public function update($condition, $newData, $options = [], $execOptions = []) {
	    $metadata = [];
	    if (isset($condition['_id'])) {
		    $metadata['_id'] = $condition['_id'];
	    }
	    
	    $this->checkPermissions("update", $metadata);
	    
		return parent::update($condition, $newData, $options, $execOptions);
    }

    // -- PHP 8.3 / yii2-mongodb 3.0+: Added $execOptions parameter
    public function save($data, $options=[], $execOptions=[]) {
    	$operation = "insert";
    	$metadata = [];
    	
    	if (isset($data['_id']) || isset($data->_id)) {
    		$operation = "update";
    		
    		if (isset($data['_id'])) {
    			$metadata['_id'] = $data['_id'];
    		} elseif (isset($data->_id)) {
    			$metadata['_id'] = $data->_id;
    		}
    	}

    	$this->checkPermissions($operation, $metadata);
    	return parent::save($data, $options, $execOptions);
    }
    
    // -- PHP 8.3 / yii2-mongodb 3.0+: Added $execOptions parameter
    public function remove($condition = [], $options=[], $execOptions=[]) {
	    $metadata = [];
	    if (isset($condition['_id'])) {
		    $metadata['_id'] = $condition['_id'];
	    }

    	$this->checkPermissions("delete", $metadata);
    	
    	return parent::remove($condition, $options, $execOptions);
		}
		
		// -- PHP 8.3 / yii2-mongodb 3.0+: Added $execOptions parameter
		public function count($condition = [], $options = [], $execOptions = [])
		{
			/**
			 * DataGrid sometimes passes null / false to the condition, so
			 * need to ensure we have an array
			 */
			if (!$condition) {
				$condition = [];
			}

			$condition = $this->buildPermissionFilter('find', $condition);

			if ($condition === false) {
				// if no permission, return 0
				return 0;
			}

			return parent::count($condition, $options, $execOptions);
		}
    
    private function checkPermissions($operation, $metadata=[]) {
	    if ($this->checkPermissions) {
			$filter = \Yii::$app->rbac->canAccessCollection($this->name, $operation, $metadata);
			
			if ($filter === false) {
				$message = "No permission to perform $operation on model ".$this->name;
				if (isset($metadata['_id'])) {
					$message .= ' ('.$metadata['_id'].')';
				}
				
				throw new PermissionDeniedException($message);
			}

			return $filter;
		}
		
		return true;
    }
	
}