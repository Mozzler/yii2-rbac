<?php
namespace mozzler\rbac\policies\model;

use mozzler\rbac\policies\BasePolicy;

/**
 * Policy to generate a database filter restricting access to
 * records owned by the current logged in user
 */
class IsOwnerModelPolicy extends BasePolicy {
	
	public $idAttribute = '_id';
	public $ownerAttribute = 'insertedUserid';
	
	public function run() {
		$user = \Yii::$app->user->identity;
		
		if (!$user) {
			return false;
		}
		
		return [
			$this->idAttribute => $user->__get($this->ownerAttribute)
		];
	}
	
}

?>