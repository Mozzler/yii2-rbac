<?php
namespace mozzler\rbac\mongodb;

use yii\mongodb\ActiveQuery as BaseActiveQuery;
use yii\helpers\ArrayHelper;

/**
 * Custom ActiveQuery class that supports passing the `rbacOperation`
 * and `checkPermissions` properties to the MongoDB Collection
 */
class ActiveQuery extends BaseActiveQuery {

	public $checkPermissions = false;
	public $rbacOperation;
	
	public function all($db = null) {
		$this->rbacOperation = 'find';
    	return parent::all($db);
    }
    
    public function one($db = null)
    {
    	$this->rbacOperation = 'find';
    	return parent::one($db);
    }

    public function count($q = '*', $db=null)
    {
        $this->rbacOperation = 'find';
        return parent::count($q, $db);
    }
    
    public function getCollection($db = null) {
        $collection = parent::getCollection($db);
        $collection->checkPermissions = $this->checkPermissions;
        $collection->rbacOperation = $this->rbacOperation;
        return $collection;
    }

}

?>