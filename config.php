<?php

return [
	'policyPaths' => [
		'@app/rbac/policies',
		'@mozzler/rbac/policies'
	],
	'registeredUserRoles' => ['registered'],
	'adminRole' => 'admin',
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
	],
	'policies' => []
];