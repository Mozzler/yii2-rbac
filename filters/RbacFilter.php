<?php
namespace mozzler\rbac\filters;

use Yii;
use yii\base\ActionFilter;
use yii\web\ForbiddenHttpException;

class RbacFilter extends ActionFilter
{
	
	public function beforeAction($action)
    {
	    if (!\Yii::$app->rbac->canAccessAction($action))
	    {
		    throw new ForbiddenHttpException("No permission to access this page");
	    }

        return parent::beforeAction($action);
    }
    
    public static function rbac() {
	    return [];
    }
    
}