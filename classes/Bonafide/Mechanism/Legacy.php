<?php defined('SYSPATH') or die('No direct script access.');
/**
 * Bonafide is a flexible authentication system for the Kohana Framework.
 *
 * This mechanism provides support for legacy Auth password hashing.
 *
 * @package    Bonafide
 * @category   Mechanisms
 * @author     Woody Gilk <woody.gilk@kohanaframework.org>
 * @copyright  (c) 2011 Woody Gilk
 * @license    MIT
 */
class Bonafide_Mechanism_Legacy extends Bonafide_Mechanism {

	public function check($password, $hash, $salt = NULL, $iterations = NULL)
	{
		// Legacy auth stores the salt in the hash
		$salt = Auth::instance()->find_salt($hash);

		return parent::check($password, $hash, $salt, 1);
	}

	public function hash($password, $salt = NULL, $iterations = NULL)
	{
		if ($salt === NULL)
		{
			// Legacy auth uses FALSE for no salt
			$salt = FALSE;
		}

		// Hash the password, only one iteration supported
		return parent::hash($password, $salt, 1);
	}

	protected function _hash($input, $salt = NULL)
	{
		// Hash the password using legacy auth
		return Auth::instance()->hash_password($input, $salt);
	}

} // End Bonafide_Mechansim_Legacy
