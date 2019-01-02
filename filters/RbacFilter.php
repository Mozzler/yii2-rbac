<?php
namespace mozzler\rbac\filters;

use Yii;
//use yii\base\ActionFilter;
use yii\base\Controller;
use yii\web\ForbiddenHttpException;
use filsh\yii2\oauth2server\exceptions\HttpException;

class RbacFilter extends \yii\base\Behavior
{

	public function events()
    {
        return [
        	Controller::EVENT_BEFORE_ACTION => 'beforeAction'
        ];
    }
    
    public function beforeAction($event)
    {   
	    // Check if OAuth2 token is valid
	    $response = \Yii::$app->getModule('oauth2')->getServer()->getResponse();

        $isValid = true;
        if($response !== null) {
            $isValid = $response->isInformational() || $response->isSuccessful() || $response->isRedirection();
        }
	    
	    // Check if RBAC permissions permit access to this controller
	    if (!\Yii::$app->rbac->canAccessAction($event->action))
	    {
		    if(!$isValid) {
	            throw new HttpException($response->getStatusCode(), $this->getErrorMessage($response), $response->getParameter('error_uri'));
	        }
	        
		    throw new ForbiddenHttpException("No permission to access this page");
	    }
    }
    
    protected function getErrorMessage(\OAuth2\Response $response)
    {
        $message = \Yii::$app->getModule('oauth2')->t('common', $response->getParameter('error_description'));
        if($message === null) {
            $message = \Yii::$app->getModule('oauth2')->t('common', 'An internal server error occurred.');
        }
        return $message;
    }
    
}