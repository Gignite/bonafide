<?php defined('SYSPATH') or die('No direct script access.');
/**
 * Bona Fide is a flexible authentication system for the Kohana Framework.
 *
 *
 * @package    Bona Fide
 * @category   Base
 * @author     Woody Gilk <woody.gilk@kohanaframework.org>
 * @copyright  (c) 2011 Woody Gilk
 * @license    MIT
 */
class Bonafide_Mechanism_Hash extends Bonafide_Mechanism {

	/**
	 * @param  string  hash algorithm
	 */
	public $type = 'sha256';

	/**
	 * @param  string  shared secret key
	 */
	public $key = NULL;

	protected function _hash($input, $salt = NULL)
	{
		// If no key is defined, this is the equivalent of calling hash()
		return hash_hmac($this->type, $input.$salt, $this->key);
	}

} // End Bonafide_Mechansim_Hash
