<?php
namespace mozzler\rbac\policies;

class BasePolicy extends \yii\base\Component {
	
	public function run() {
		return false;
	}
	
}

?>