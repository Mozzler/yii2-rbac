<?php
namespace mozzler\rbac\policies;

use mozzler\rbac\policies\BasePolicy;
use mozzler\base\components\Tools;

/**
 * Policy to generate a database filter restricting access to
 * records owned by the current logged in user
 */
class IsOwnerModelPolicy extends BasePolicy {
	
	public $idAttribute = '_id';
	public $ownerAttribute = 'createdUserId';
	
	public function run($params=[]) {
		$user = \Yii::$app->user->getIdentity();
		
		if (!$user) {
			return false;
		}

		$match = $user->__get($this->idAttribute);

		if (substr($this->idAttribute,-2) == 'Id' || $this->idAttribute == '_id') {
			$match = Tools::ensureId($match);
		}

		return [
			$this->ownerAttribute => $match
		];
	}
	
}

?>