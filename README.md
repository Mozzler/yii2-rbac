
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

## Configuration

```
$config['modules']['rbac'] = [
	'class' => '\mozzler\rbac\Module',
	
	// Location of a custom configuration file that can be used instead
	// of putting all your configuration in your main config file
	'rbacConfigFile' => "config/rbac.php",
	
	// default policy paths
	'policyPaths' => [
		'@app/rbac/policies',
		'@mozzler/rbac/policies'
	],
	
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

## Usage

### Defining policies

### Defining roles

### Linking policies and roles