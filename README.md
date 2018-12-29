
## Installation

Add the following to the application config:

```
// add rbac to bootstrap
$config['bootstrap'] = ['log','rbac'];

// add rbac component
$config['components']['rbac'] = [
	'class' => '\mozzler\rbac\components\RbacManager'
];

// add the rbac module
$config['modules']['rbac'] = [
	'class' => '\mozzler\rbac\Module'
];
```

All `ActiveRecord` models must extend from `mozzler\rbac\mongodb\ActiveRecord` (currently only MongoDB support exists). This ensures the Model Permissions are correctly hooked into this RBAC Module.

The User model used in the application (see application config (`['components']['user']['class']`) must have a `findIdentity()` method that disables disables permission checks when searching for a User. This is so that logged in users can be located in the database.

For example:

```
public static function findIdentity($id)
{
    // Don't check permissions when finding an Identity
    return self::findOne($id, false);
}
```

## Configuration

```
$config['modules']['rbac'] = [
	'class' => '\mozzler\rbac\Module',
	
	// Location of a custom configuration file that can be used instead
	// of putting all your configuration in your main config file
	'rbacConfigFile' => "config/rbac.php",
	
	// default roles
	'roles' => [
		'public' => [
			'name' => 'Public'
		],
		'admin' => [
			'name' => 'Administrator'
		],
		'registered' => [
			'name' => 'Registered User'
		]
	]
];
```

## How it works

Users are linked to many Roles. Roles in turn are linked to many Policies. Policies are applied to either controller actions or model queries.

Action policies will enable / disable access to the requested action based on the current user's roles.

Model policies will restrict access to model queries (`find()`, `insert()`, `update()`, `delete()`). A policy that generates a `false` response disables all access. A policy may return an array which is a filter applied to the model query.

### Verification process

TLDR; If no policies apply, access is granted. If policies apply, at least one policy must return `true` (or a database filter) otherwise access is denied.

The process for verifying a model / action request is as follows:

1. Establish the roles that apply for the logged in user
1. Establish the policies that apply for the current request, based on the user's roles and the current request type (ie: mozzler.base.models.Model/index)
1. If no policies are found, access is granted
1. If any policies return `true`, access is granted
1. If any model policies return a filter, access granted however the returned filter is applied to the database query
1. If policies are found and there is no filter result or `true` result, access is denied
1. Where more than one policy returns a filter, all the filters are applied using `OR` meaning any filter can match and provide access

### Defaults

The following defaults are applied to verification requests:

1. If a user isn't logged in, they automatically receive the `public` role (unless changed in config)
1. If a user is logged in, they automatically receive the `registered` role (unless changed in config)
1. If the user is an administrator they will automatically be granted unrestricted access and no policies are checked

### Defining roles

Define roles in the `mozzler\rbac\Module` configuration option `roles`:

```
'roles' => [
	'public' => [
		'name' => 'Public'
	],
	'admin' => [
		'name' => 'Administrator'
	],
	'registered' => [
		'name' => 'Registered User'
	]
]
```

### Linking policies and roles

Policies are linked to roles within a static `rbac()` method on the controller or model, or via the RBAC configuration.

Note: The `rbac()` method does NOT merge with parent::rbac(). The RBAC manager handles this merging as it needs to incorporate any configuration via a custom configuration file into the merging process.

For example, override the static `rbac()` method in a controller:

```
namespace app\controllers;

class MyController extends \yii\web\Controller {
	public static function rbac()
	{
		return [
			// define policies for users in the role 'registered'
			'registered' => [
				// grant access to the index action on this controller
				'index' => [
					'grant' => true
				]
			]
		]);
	}
	
}
```

For example, override the `rbac()` method in a model:

```
namespace app\models;

class MyModel extends \yii\mongodb\ActiveRecord {

	public static function rbac()
	{
		return [
			// define policies for users in the role 'registered'
			'registered' => [
				// allow finding of all records
				'find' => [
					'grant' => true
				],
				// allow deleting of records owned by the current user
				// using a built in policy
				'delete' => [
					'delete-own' => '\mozzler\rbac\policies\model\IsOwnerModelPolicy'
				],
				// allow updating records, but only linked to the current user
				// using a built in policy, but providing custom configuration
				'update' => [
					'update-own' => [
						'class' => '\mozzler\rbac\policies\model\IsOwnerModelPolicy',
						'ownerAttribute' => 'ownerId'
					]
				]
			]
		];
	}
}
```

Defining the RBAC rules in a controller or model is ideal for defining defaults. These can then be overridden or extended by creating custom RBAC rules in the configuration file.

These are defined in a custom `/config/rbac.php` (or alternative if customised in the `rbac` component configuration) file. The above rules would be defined as follows:

```
<?php
return [
	'policies' => [
		// define policies that apply to the 'registered' role
		'registered' => [
			// define policies that apply to MyController
			'app\controllers\MyController' => [
				'index' => [
					'grant' => true
				]
			],
			'app\models\MyModel' => [
				// allow finding of all records
				'find' => [
					'grant' => true
				],
				// allow deleting of records owned by the current user
				// using a built in policy
				'delete' => [
					'delete-own' => '\mozzler\rbac\policies\model\IsOwnerModelPolicy'
				],
				// allow updating records, but only linked to the current user
				// using a built in policy, but providing custom configuration
				'update' => [
					'update-own' => [
						'class' => '\mozzler\rbac\policies\model\IsOwnerModelPolicy',
						'ownerAttribute' => 'ownerId'
					]
				]
			]
		]
	]
];
```

Every policy has it's own name which allows for easy customising or disabling a policy.

Assume we were inheriting the `rbac()` policies, we could then customise or disable those default policy rules in our `/config/rbac.php` file:

```
<?php
return [
	'policies' => [
		// define policies that apply to the 'registered' role
		'registered' => [
			// define policies that apply to MyController
			'app\controllers\MyController' => [
				// Disable the grant permission for the index page, so registered
				// users can no longer access this controller's index page
				'index' => [
					'grant' => false
				]
			],
			'app\models\MyModel' => [
				// Disable the delete own policy and grant unrestricted access,
				// so registered users can delete any model
				'delete' => [
					'delete-own' => false,
					'grant' => true
				],
				// Customise the ownerAttribute for the update own policy.
				// Class continues to be inherited.
				'update' => [
					'update-own' => [
						'ownerAttribute' => 'insertedUserId'
					]
				]
			]
		]
	]
];
```

### Policy inheritance

Policies follow class inheritance to build a list of all the available policies to check.

For example, assume a controller (`SiteController`) has the following inheritance hierarchy:

- yii\base\Controller
- yii\web\Controller
- app\controllers\Base
- app\controllers\SiteController

The RBAC policies will be built from all four of those controllers, merged in the following order:

1. yii\base\Controller::rbac()
1. RBAC config file for `yii\base\Controller`
1. yii\web\Controller::rbac()
1. RBAC config file for `yii\web\Controller`
1. app\controllers\Base::rbac()
1. RBAC config file for `app\controllers\Base`
1. app\controllers\SiteController::rbac()
1. RBAC config file for `app\controllers\SiteController`

### Writing policies

You can write your own policies by extending `mozzler\rbac\policies\BasePolicy`.

For example, see the simple `GrantPolicy` which takes a `grant` property to define whether the policy should grant access:

```
<?php
namespace mozzler\rbac\policies;

/**
 * Policy that always returns true, for testing
 */
class GrantPolicy extends BasePolicy {
	
	public $grant = true;
	
	public function run() {
		return $this->grant;
	}
	
}

?>
```

The `run()` method can perform any logic to return:

- `true`: Grant full access
- `false`: Don't grant access via this policy
- `filter(Array)`: PHP Array as a filter to apply to database results (Only applies to policies linked to models)

