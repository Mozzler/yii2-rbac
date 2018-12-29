<?php
namespace mozzler\rbac\mongodb;

use \yii\helpers\ArrayHelper;
use \yii\base\InvalidConfigException;
use \yii\db\StaleObjectException;

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
    
    /**
	 * Add support for permission checks
	 *
	 * @see \yii\mongodb\ActiveRecord::insert()
	 * @param	boolean		$runValidation		Whether to run validation rules when saving this model.
	 * @param	array		$attributes 		List of attributes that need to be inserted. Defaults to `null`, meaning all attributes that are loaded from DB will be saved.
	 * @param	boolean		$checkPermissions	Whether to check permissions based on the current logged in user.
	 * @return	boolean		Whether the save succeeded.
	 */
    public function insert($runValidation = true, $attributes = null, $checkPermissions=true)
    {
        if ($runValidation && !$this->validate($attributes)) {
            return false;
        }
        
        return $this->insertInternal($attributes, $checkPermissions);
    }
    
    /**
	 * Add support for permission checks
	 *
	 * @ignore
	 * @see \yii\mongodb\ActiveRecord::insertInternal()
	 * @param	array		$attributes 		List of attributes that need to be inserted. Defaults to `null`, meaning all attributes that are loaded from DB will be saved.
	 * @param	boolean		$checkPermissions	Whether to check permissions based on the current logged in user.
	 * @return	boolean		Whether the save succeeded.
	 */
    protected function insertInternal($attributes = null, $checkPermissions=true)
    {
        if (!$this->beforeSave(true)) {
            return false;
        }
        
        $values = $this->getDirtyAttributes($attributes);
        if (empty($values)) {
            $currentAttributes = $this->getAttributes();
            foreach ($this->primaryKey() as $key) {
                if (isset($currentAttributes[$key])) {
                    $values[$key] = $currentAttributes[$key];
                }
            }
        }
        
        $collection = static::getCollection();
        $collection->checkPermissions = $checkPermissions;
        $newId = $collection->insert($values, [], true);
        $this->setAttribute('_id', $newId);
        $values['_id'] = $newId;
        $changedAttributes = array_fill_keys(array_keys($values), null);
        $this->setOldAttributes($values);
        $this->afterSave(true, $changedAttributes);
        return true;
    }
    
    /**
	 * Add support for permission checks
	 *
	 * @see \yii\mongodb\ActiveRecord::update()
	 * @param	boolean		$runValidation		Whether to run validation rules when updating this model.
	 * @param	array		$attributes 		List of attributes that need to be updated. Defaults to `null`, meaning all attributes that are loaded from DB will be updated.
	 * @param	boolean		$checkPermissions	Whether to check permissions based on the current logged in user.
	 * @return	boolean		Whether the update succeeded.
	 */
    public function update($runValidation = true, $attributeNames = null, $checkPermissions=true)
    {
        if ($runValidation && !$this->validate($attributeNames)) {
            return false;
        }

        return $this->updateInternal($attributeNames, $checkPermissions);
    }
    /**
	 * Add support for permission checks
	 *
	 * @ignore
	 * @see \yii\mongodb\ActiveRecord::updateInternal()
	 * @param	array		$attributes 		List of attributes that need to be updated. Defaults to `null`, meaning all attributes that are loaded from DB will be updated.
	 * @param	boolean		$checkPermissions	Whether to check permissions based on the current logged in user.
	 * @return	boolean		Whether the update succeeded.
	 */
    protected function updateInternal($attributes = null, $checkPermissions=true)
    {
        if (!$this->beforeSave(false)) {
            return false;
        }
        $values = $this->getDirtyAttributes($attributes);
        if (empty($values)) {
            $this->afterSave(false, $values);
            return 0;
        }
        $condition = $this->getOldPrimaryKey(true);
        $lock = $this->optimisticLock();
        if ($lock !== null) {
            if (!isset($values[$lock])) {
                $values[$lock] = $this->$lock + 1;
            }
            $condition[$lock] = $this->$lock;
        }
        // We do not check the return value of update() because it's possible
        // that it doesn't change anything and thus returns 0.
        $collection = static::getCollection();
        $collection->checkPermissions = $checkPermissions;
        $rows = $collection->update($condition, $values, [], true);
        if ($lock !== null && !$rows) {
            throw new StaleObjectException('The object being updated is outdated.');
        }
        $changedAttributes = [];
        foreach ($values as $name => $value) {
            $changedAttributes[$name] = $this->getOldAttribute($name);
            $this->setOldAttribute($name, $value);
        }
        $this->afterSave(false, $changedAttributes);
        return $rows;
    }
    
    /**
	 * Add support for permission checks
	 *
	 * @see \yii\mongodb\ActiveRecord::save()
	 * @param	boolean		$runValidation		Whether to run validation rules when saving this model.
	 * @param	array		$attributeNames 	List of attribute names that need to be saved. Defaults to `null`, meaning all attributes that are loaded from DB will be saved.
	 * @param	boolean		$checkPermissions	Whether to check permissions based on the current logged in user.
	 * @return	boolean		Whether the save succeeded.
	 *
	 * @internal Override base save method to gracefully turn duplicate key exceptions into errors
	 */
    public function save($runValidation = true, $attributeNames = null, $checkPermissions=true) {
		if ($this->getIsNewRecord()) {
            return $this->insert($runValidation, $attributeNames, $checkPermissions);
        } else {
            return $this->update($runValidation, $attributeNames, $checkPermissions) !== false;
        }
	}
	
	// TODO: Add checkPermission support to delete
}
	
?>