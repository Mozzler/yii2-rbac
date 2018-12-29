<?php
namespace mozzler\rbac\mongodb;

use \yii\helpers\ArrayHelper;
use \yii\base\InvalidConfigException;

/**
 * Custom ActiveRecord class that registers an ActiveRecord model
 * with the RBAC component when initialised.
 *
 * It also adds `checkPermissions` support to the underlying
 * Mongo query methods such as `find()`.
 */
class ActiveRecord extends \yii\mongodb\ActiveRecord {
	
	public function init() {
		parent::init();
		
		\Yii::$app->rbac->registerModel($this->collectionName(), $this->className());
	}
	
	/**
     * Add support for permission checks
     *
     * @see \yii\base\Model::beforeSave()
     * @param	boolean		$checkPermissions	Whether to check permissions based on the current logged in user.
     */
    public static function findOne($condition, $checkPermissions=true) {
        return static::findByCondition($condition, $checkPermissions)->one();
    }
    
    /**
     * Add support for permission checks
     *
     * @ignore
     * @see \yii\base\Model::beforeSave()
     * @param	boolean		$checkPermissions	Whether to check permissions based on the current logged in user.
     */
    protected static function findByCondition($condition, $checkPermissions=true) {
        $query = static::find($checkPermissions);

        if (!ArrayHelper::isAssociative($condition)) {
            // query by primary key
            $primaryKey = static::primaryKey();
            if (isset($primaryKey[0])) {
                $condition = [$primaryKey[0] => $condition];
            } else {
                throw new InvalidConfigException('"' . get_called_class() . '" must have a primary key.');
            }
        }
        
        return $query->andWhere($condition);
    }
    
    /**
     * Add support for permission checks
     *
     * @see \yii\base\Model::beforeSave()
     * @param	boolean		$checkPermissions	Whether to check permissions based on the current logged in user.
     */
	public static function find($checkPermissions=true) {
		$query = \Yii::createObject(ActiveQuery::className(), [get_called_class()]);
		$query->checkPermissions = $checkPermissions;
		return $query;
    }
	
}
	
?>