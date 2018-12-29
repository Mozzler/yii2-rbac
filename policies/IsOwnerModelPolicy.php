<?php
namespace mozzler\rbac\policies;

use mozzler\rbac\policies\BasePolicy;

/**
 * Policy to generate a database filter restricting access to
 * records owned by the current logged in user
 */
class IsOwnerModelPolicy extends BasePolicy {
	
	public $idAttribute = '_id';
	public $ownerAttribute = 'createdUserId';
	
	public function run() {
		$user = \Yii::$app->user->getIdentity();
		
		if (!$user) {
			return false;
		}
		
		return [
			$this->ownerAttribute => strval($user->__get($this->idAttribute))
		];
	}
	
}

?>