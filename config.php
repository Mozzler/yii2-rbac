<?php

return [
	'policyPaths' => [
		'@app/rbac/policies',
		'@mozzler/rbac/policies'
	],
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