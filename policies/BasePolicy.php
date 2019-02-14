<?php
namespace mozzler\rbac\policies;

class BasePolicy extends \yii\base\Component {
	
	public function run($params=[]) {
		return false;
	}
	
}

?>