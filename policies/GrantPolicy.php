<?php
namespace mozzler\rbac\policies;

/**
 * Policy that always returns true, for testing
 */
class GrantPolicy extends BasePolicy {
	
	public $grant = true;
	
	public function run() {
		return $this->grant;
	}
	
}

?>