<?php defined('SYSPATH') or die('No direct script access.');
/**
 * Bonafide is a flexible authentication system for the Kohana Framework.
 *
 * This mechanism provides support for bcrypt password hashing.
 * 
 * bcrypt is highly recommended by many to safely store passwords. For more
 * information, see http://codahale.com/how-to-safely-store-a-password/
 *
 * @package    Bonafide
 * @category   Mechanisms
 * @author     Wouter <wouter.w@gmx.net>
 * @author     Woody Gilk <woody.gilk@kohanaframework.org>
 * @copyright  (c) 2011 Wouter
 * @copyright  (c) 2011 Woody Gilk
 * @license    MIT
 */
class Bonafide_Mechanism_Bcrypt extends Bonafide_Mechanism {

	// Allowed salt characters
	const SALT = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

	/**
	 * @param  integer  number between 4 and 31, base-2 logarithm of the iteration count
	 */
	public $cost = 12;

	public function __construct(array $config = NULL)
	{
		if ( ! defined('CRYPT_BLOWFISH') OR ! CRYPT_BLOWFISH)
		{
			throw new Bonafide_Exception('This server does not support bcrypt hashing');
		}

		parent::__construct($config);
	}

	public function hash($password, $salt = NULL, $iterations = NULL)
	{
		if ( ! $salt)
		{
			// Generate a random 22 character salt
			$salt = Text::random(self::SALT, 22);
		}

		if ( ! $iterations)
		{
			// Use the default cost
			$iterations = $this->cost;
		}

		// Apply 0 padding to the iterations, normalize to a range of 4-31
		$iterations = sprintf('%02d', min(31, max($iterations, 4)));

		// Create a salt suitable for bcrypt
		$salt = '$2a$'.$iterations.'$'.$salt.'$';

		return $this->_hash($password, $salt);
	}

	protected function _hash($input, $salt = NULL)
	{
		return crypt($input, $salt);
	}

	public function check($password, $hash, $salt = NULL, $iterations = NULL)
	{
		// $2a$ (4) 00 (2) $ (1) <salt> (22)
		preg_match('/^\$2a\$(\d{2})\$(.{22})/D', $hash, $matches);

		// Extract the iterations and salt from the hash
		list($_, $iterations, $salt) = $matches;

		return parent::check($password, $hash, $salt, $iterations);
	}

} // End Bonafide_Mechansim_Bcrypt

