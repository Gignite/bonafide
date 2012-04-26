<?php defined('SYSPATH') or die('No direct script access.');
/**
 * PBKDF2 derived key mechanism for Bona Fide
 *
 * @package    Bonafide
 * @category   Mechanisms
 * @author     Isaiah DeRose-Wilson <isaiah.derosewilson@kohanaframework.org>
 * @copyright  (c) 2011 Isaiah DeRose-Wilson
 * @license    MIT
 */
class Bonafide_Mechanism_PBKDF2 extends Bonafide_Mechanism {

	/**
	 * @param  string  hash algorithm
	 */
	public $type = 'sha1';

	/**
	 * @param  int  number of iterations to use
	 */
	public $iterations = 1000;

	/**
	 * @param  int  length of derived key to create
	 */
	public $length = 40;

	/**
	 * This mechanism provides support for the creation of derived keys using PBKDF2.
	 * PBKDF2 is explained by rfc2898. It is recommended that the salt value be
	 * at least 64 bits (8 octets) long, and a minimum of a 1000 iterations are used.
	 *
	 *     $config = array(
	 *      'type'       => 'sha512',
	 *      'iterations' => 10000,
	 *      'length'     => 128,
	 *     );
	 *
	 *     $hash = Bonafide::mechanism('PBKDF2', $config)
	 *                ->hash('mySuperSecretPassword', 'aRandomSaltHere');
	 *
	 * You can also (more common usage) set your hash settings in the Bonafide
	 * config file and use the [Bonafide::instance] method to create your
	 * hash mechanism.
	 *
	 * [!!] The iteration count can not be set using this method
	 *
	 * @link    http://www.ietf.org/rfc/rfc2898.txt
	 * @param   string   plaintext password
	 * @param   string   appended salt, should be unique per user
	 * @param   integer  number of iterations to run
	 * @return  string  base64 encoded derived key
	 */
	public function hash($password, $salt = NULL, $iterations = NULL)
	{
		return $this->_hash($password, $salt);
	}

	/**
	 * Internal method for creating the derived key
	 *
	 * @param   string  input text
	 * @param   string  appended salt
	 * @return  string  base64 encoded derived key
	 */
	protected function _hash($input, $salt = NULL)
	{
		// Number of blocks needed to create the derived key
		$block_count = ceil($this->length / strlen(hash($this->type, NULL, TRUE)));

		$output = '';

		for ($i = 1; $i <= $block_count; $i++)
		{
			// Initial hash
			$ib = $block = hash_hmac($this->type, $salt.pack('N', $i), $input, TRUE);

			// Iterations
			for ($j = 1; $j < $this->iterations; $j++)
			{
				$ib ^= ($block = hash_hmac($this->type, $block, $input, TRUE));
			}

			$output .= $ib;
		}

		// Base64 encode output to make storage easier
		return base64_encode(substr($output, 0, $this->length));
	}

	/**
	 * Check a plaintext password against the derived key of that password.
	 *
	 * [!!] The iteration count can not be set using this method
	 *
	 * @param   string   plaintext password
	 * @param   string   hashed password
	 * @param   string   appended salt, should be unique per user
	 * @param   integer  number of iterations to run
	 * @return  boolean
	 */
	public function check($password, $hash, $salt = NULL, $iterations = NULL)
	{
		return $hash === $this->_hash($password, $salt);
	}

} // End Bonafide_Mechansim_Hash
