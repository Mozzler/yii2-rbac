<?php
namespace mozzler\rbac\filters;

use mozzler\auth\yii\oauth\auth\CompositeAuth as BaseCompositeAuth;
use yii\web\ForbiddenHttpException;

class CompositeAuth extends BaseCompositeAuth {
	
	/*protected $accessGranted = true;
	
	public function beforeAction($action) {
		\Yii::trace("Composite Auth in mozzler");
		// Create an instance of the user identity class to ensure it exists
		// and maps RBAC permissions for users
	    //\Yii::createObject(\Yii::$app->user->identityClass);
	    
	    // Execute OAuth2 library actions
	    parent::beforeAction($action);
	    
		if (!\Yii::$app->rbac->canAccessAction($action)) {
			//throw new ForbiddenHttpException("No permission to access this page");
			$this->accessGranted = false;
			\Yii::warning("No permission to access page");
		}
		
		return true;
	}*/
	
}


		