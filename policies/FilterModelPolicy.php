<?php
namespace mozzler\rbac\policies;

/**
 * Policy that returns a supplied filter to apply on queries
 */
class FilterModelPolicy extends BasePolicy {
	
	public $filter = [];
	
	public function run($params=[]) {
		return $this->filter;
	}
	
}

?>