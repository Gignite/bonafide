<?php defined('SYSPATH') or die('No direct script access.');

// Add demo route
Route::set('bonafide', 'bonafide(/<action>)')
	->defaults(array(
		'controller' => 'bonafide',
	));
