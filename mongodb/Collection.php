<?php
namespace mozzler\rbac\mongodb;

use yii\mongodb\Collection as BaseCollection;

/**
 * Custom Collection class that adds `checkPermission` and
 * `rbacOperation` support to MongoDB Collection
 */
class Collection extends BaseCollection {
	
	public $checkPermissions = true;
	public $rbacOperation;
	
	public function find($condition=[], $fields=[], $options=[]) {
		$condition = $this->buildPermissionFilter('find', $condition);
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
		} else if ($filter) {
			// apply the filter as an AND on the query
			$condition = array_merge(['AND'], [$condition, $filter]);
		}
		
		return $condition;
	}
	
}