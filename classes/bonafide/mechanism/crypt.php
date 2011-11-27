<?php defined('SYSPATH') or die('No direct script access.');
/**
 * This mechanism provides support for PHP [One-way string hashing](http://php.net/manual/en/function.crypt.php).
 * 
 * Currently, only support 3 hashing type: blowfish, sha256, sha512
 * 
 * @package    Bonafide
 * @category   Mechanisms
 * @author     Wouter <wouter.w@gmx.net>
 * @author     Devi Mandiri <devi.mandiri@gmail.com>
 * @copyright  (c) 2011 Wouter
 * @copyright  (c) 2011 Devi Mandiri
 * @license    MIT
 */
class Bonafide_Mechanism_Crypt extends Bonafide_Mechanism {

	/**
	 * @param  string  hash algorithm
	 */
	public $type = 'blowfish';

	/**
	 * Pre-check supported hashing mechanism.
	 *
	 * @param  array  configuration
	 */
	public function __construct(array $config = NULL)
	{
		parent::__construct($config);

		$hash = strtoupper($this->type);

		$hash = "CRYPT_{$hash}";

		if ( ! defined($hash) OR ! $hash)
		{
			throw new Bonafide_Exception('This server does not support :hash hashing',
				array(':hash' => $hash));
		}
	}

	public function hash($password, $salt = NULL, $iterations = NULL)
	{
		$iterations = (int) $iterations;

		switch (strtolower($this->type))
		{
			case 'sha256':
				$salt = $this->sha($salt, $iterations);
			break;

			case 'sha512':
				$salt = $this->sha($salt, $iterations, 6);
			break;

			// default blowfish
			default:
				$salt = $this->blowfish($salt, $iterations);
			break;
		}

		return $this->_hash($password, $salt);
	}

	protected function _hash($input, $salt = NULL)
	{
		return crypt($input, $salt);
	}

	/**
	 * Blowfish hashing.
	 * 
	 * @param  string  input salt
	 * @param  int     number between 4 and 31, base-2 logarithm of the iteration count
	 * @return string
	 */
	protected function blowfish($salt = NULL, $iterations = NULL)
	{
		if ( ! $salt)
		{
			// Generate a random 22 character salt
			$salt = Text::random('alnum', 22);
		}

		if ($iterations === NULL)
		{
			$iterations = 12;
		}

		// Apply 0 padding to the iterations, normalize to a range of 4-31
		$iterations = sprintf('%02d', min(31, max($iterations, 4)));

		// Create a salt suitable for bcrypt
		return '$2a$'.$iterations.'$'.$salt.'$';
	}

	/**
	 * SHA256/SHA512 hashing.
	 * 
	 * @param  string  input salt
	 * @param  int     number between 1000 and 99999999
	 * @param  int     SHA256 => 5, SHA512 => 6
	 * @return string
	 */
	protected function sha($salt = NULL, $iterations, $round = 5)
	{
		if ( ! $salt)
		{
			$salt = Text::random('alnum', 16);
		}

		// Truncate salt to 16 chars
		$salt = substr($salt, 0, 16);

		$iterations = Valid::range($iterations, 1000, 99999999) ? $iterations : 5000;

		return'$'.$round.'$rounds='.$iterations.'$'.$salt.'$';
	}

	public function check($password, $hash, $salt = NULL, $iterations = NULL)
	{
		switch (strtolower($this->type))
		{
			case 'sha256':
				return $this->sha_check($password, $hash, $salt, $iterations);
			break;

			case 'sha512':
				return $this->sha_check($password, $hash, $salt, $iterations, 6);
			break;

			// default blowfish
			default:
				return $this->blowfish_check($password, $hash, $salt, $iterations);
			break;
		}
	}

	protected function blowfish_check($password, $hash, $salt = NULL, $iterations = NULL)
	{
		// $2a$ (4) 00 (2) $ (1) <salt> (22)
		preg_match('/^\$2a\$(\d{2})\$(.{22})/D', $hash, $matches);

		// Extract the iterations and salt from the hash
		list($_, $iterations, $salt) = $matches;

		return parent::check($password, $hash, $salt, $iterations);
	}

	protected function sha_check($password, $hash, $salt = NULL, $iterations = NULL, $round = 5)
	{
		if (preg_match('/^\$(['.$round.'])\$rounds=(\d+)\$(.{16})/D', $hash, $matches))
		{
			list($_, $_, $iterations, $salt) = $matches;

			return parent::check($password, $hash, $salt, $iterations);
		}

		return FALSE;
	}

} // End Bonafide Mechanism Crypt
