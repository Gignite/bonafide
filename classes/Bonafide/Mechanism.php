<?php defined('SYSPATH') or die('No direct script access.');
/**
 * Bonafide is a flexible authentication system for the Kohana Framework.
 *
 * @package    Bonafide
 * @category   Base
 * @author     Woody Gilk <woody.gilk@kohanaframework.org>
 * @copyright  (c) 2011 Woody Gilk
 * @license    MIT
 */
abstract class Bonafide_Mechanism {

	/**
	 * Applies configuration variables to the current mechanism.
	 *
	 * @param  array  configuration
	 */
	public function __construct(array $config = NULL)
	{
		if ($config)
		{
			foreach ($config as $name => $value)
			{
				if (property_exists($this, $name))
				{
					$this->$name = $value;
				}
			}
		}
	}

	/**
	 * Check a plaintext password against the hash of that password. 
	 *
	 * [!!] To increase security, use a unique salt and a random iteration
	 * count for every user!
	 *
	 * @param   string   plaintext password
	 * @param   string   hashed password
	 * @param   string   appended salt, should be unique per user
	 * @param   integer  number of iterations to run
	 * @return  boolean
	 */
	public function check($password, $hash, $salt = NULL, $iterations = NULL)
	{
		return ($hash === $this->hash($password, $salt, $iterations));
	}

	/**
	 * Hash a plaintext password and return the result, applying salt and
	 * [key strengthening](http://en.wikipedia.org/wiki/Key_strengthening).
	 *
	 * [!!] To increase security, use a unique salt and a random iteration
	 * count for every user!
	 *
	 * @param   string   plaintext password
	 * @param   string   hashed password
	 * @param   string   appended salt, should be unique per user
	 * @param   integer  number of iterations to run
	 * @return  boolean
	 */
	public function hash($password, $salt = NULL, $iterations = NULL)
	{
		// Must always be an integer!
		$iterations = (int) $iterations;

		do
		{
			// Apply strengthening to the hashed password
			$password = $this->_hash($password, $salt);
		}
		while(--$iterations > 0);

		return $password;
	}

	/**
	 * Get the hash of some text.
	 *
	 * @param   string  input text
	 * @param   string  appended salt
	 * @return  string
	 */
	abstract protected function _hash($input, $salt = NULL);

} // End Bonafide_Mechanism
