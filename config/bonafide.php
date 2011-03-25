<?php defined('SYSPATH') or die('No direct script access.');

return array(

	// Group name, multiple configuration groups are supported
	'default' => array(

		// Multiple mechanisms can be added for versioned passwords, etc
		'mechanisms' => array(

			// Put your mechanisms here! The format is:
			// string $prefix => array(string $mechanism, array $config)

			// // bcrypt hashing using Blowfish encryption
			// 'bcrypt' => array('bcrypt', array(
			// 	// number between 4 and 31, base-2 logarithm of the iteration count
			// 	'cost' => 12
			// )),

			// // pbkdf2 hashing using Blowfish encryption
			// 'pbkdf2' => array('pbkdf2', array(
			// 
			// 	// Hash type to hash algorithm use
			// 	'type' => 'sha1',
			// 
			// 	// number of iterations to use
			// 	'iterations' => 1000,
			// 
			// 	// length of derived key to create
			// 	'length' => 40,
			// )),

			// // basic HMAC hashing
			// 'hash' => array('hash', array(
			// 	// Hash type to use when calling hash_hmac()
			// 	'type' => 'sha256',
			// 
			// 	// Shared secret HMAC key
			// 	'key' => 'put your shared secret key here!',
			// )),

			// // legacy (v3.0) Auth module hashing
			// 'legacy' => array('legacy'),
		),
	),
);
