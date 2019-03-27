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
	
	public function find($condition=[], $fields=[], $options=[]) {
		$condition = $this->buildPermissionFilter('find', $condition);

		if ($condition === false) {
			// no permission, so generate a query that will always return nothing
			return parent::find(['1' => '2'], $fields, $options);
		}

		return parent::find($condition, $fields, $options);
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
	
	public function insert($data, $options = [], $throwException = false) {
    	$this->checkPermissions("insert");
    	
		return parent::insert($data, $options);
    }
    
    public function update($condition, $newData, $options = [], $throwException = false) {
	    $metadata = [];
	    if (isset($condition['_id'])) {
		    $metadata['_id'] = $condition['_id'];
	    }
	    
	    $this->checkPermissions("update", $metadata);
	    
		return parent::update($condition, $newData, $options);
    }

    public function save($data, $options=[]) {
    	$operation = "insert";
    	
    	if (isset($data['_id']) || isset($data->_id)) {
    		$operation = "update";
    		
    		$metadata = [];
		    if (isset($condition['_id'])) {
			    $metadata['_id'] = $data['_id'];
		    }
    	}

    	$this->checkPermissions($operation, $metadata);
    	return parent::save($data, $options);
    }
    
    public function remove($condition = [], $options=[]) {
	    $metadata = [];
	    if (isset($condition['_id'])) {
		    $metadata['_id'] = $condition['_id'];
	    }

    	$this->checkPermissions("delete", $metadata);
    	
    	return parent::remove($condition, $options);
		}
		
		public function count($condition = [], $options = [])
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

			return parent::count($condition, $options);
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