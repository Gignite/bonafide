<?php defined('SYSPATH') or die('No direct script access.');

return array(

	// Group name, multiple configuration groups are supported
	'default' => array(

		// Multiple mechanisms can be added for versioned passwords, etc
		'mechanisms' => array(

			// Bonafide ships with a HMAC hashing mechanism
			array('hash', array(
				// Hash prefix, must be unique for every mechanism!
				// 'prefix' => NULL,

				// Hash type to use when calling hash_hmac()
				// 'type' => 'sha256',

				// Shared secret HMAC key
				// 'key' => 'put your shared secret key here!',
			)),
		),
	),
);
