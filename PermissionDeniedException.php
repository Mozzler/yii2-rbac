<?php
namespace mozzler\rbac;

class PermissionDeniedException extends \yii\base\Exception {

	public function getName() {
		return "Permission Denied Exception";
	}

}