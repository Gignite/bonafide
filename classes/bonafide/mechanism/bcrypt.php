<?php defined('SYSPATH') or die('No direct script access.');
/**
 * This mechanism provides support for bcrypt password hashing.
 *
 * bcrypt is highly recommended by many to safely store passwords.
 * see: http://codahale.com/how-to-safely-store-a-password/
 * 
 * in short: bcrypt is slow, which makes brute force attacks very
 * time consuming. Moreover, bcrypt introduces a work
 * factor (here $cost). This allows the mechanism to keep up
 * with Moore's law. As computers get faster, you can increase
 * the work factor and the hash will get slower.
 *
 * Please note that you CAN increase the work factor ($cost)
 * at any time, even in production. Existing hashes will remain
 * valid because the work factor is actually stored in the hash
 * itself!
 */
class Bonafide_Mechanism_Bcrypt extends Bonafide_Mechanism {

	/**
	 * @param  int  A number between 4 and 31; the 'base-2 logarithm of the iteration count' --> 2^$cost
	 *              higher = more iterations = slower encryption = more secure hash.
	 */
	public $cost = 12;

	public function __construct(array $config = NULL)
	{
		if ( ! CRYPT_BLOWFISH)
		{
			throw new Bonafide_Exception('No Blowfish Encryption support on this system');
		}

		parent::_construct($config);
	}

	public function hash($password)
	{
		$salt = Text::random('alnum', 22);

		return $this->_hash($password, $salt, $this->cost);
	}

	protected function _hash($input, $salt, $cost)
	{
		return crypt($input, '$2a$' . ($cost < 10 ? '0' : '') . (int) $cost . '$' . $salt . '$');
	}

	public function check($password, $hash)
	{
		return $hash === $this->_hash($password, substr($hash,7,22), substr($hash, 4, 2));
	}

} // End Bonafide_Mechansim_Bcrypt

