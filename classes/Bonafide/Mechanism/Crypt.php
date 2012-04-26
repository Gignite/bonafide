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
 * @author     Woody Gilk <woody.gilk@kohanaframework.org>
 * @copyright  (c) 2011 Wouter
 * @copyright  (c) 2011 Devi Mandiri
 * @copyright  (c) 2011 Woody Gilk
 * @license    MIT
 */
class Bonafide_Mechanism_Crypt extends Bonafide_Mechanism {

	/**
	 * @param  string  hash algorithm
	 */
	public $type = 'blowfish';

	/**
	 * @param  integer  iterations/cost
	 */
	public $iterations = 5000;

	/**
	 * Pre-check supported hashing mechanism.
	 *
	 * @param  array  configuration
	 */
	public function __construct(array $config = NULL)
	{
		parent::__construct($config);

		// Create a constant name from the type
		$hash = 'CRYPT_'.strtoupper($this->type);

		if ( ! defined($hash))
		{
			throw new Bonafide_Exception('This server does not support :hash hashing', array(
					':hash' => $hash,
				));
		}
	}

	public function hash($password, $salt = NULL, $iterations = NULL)
	{
		$iterations = (int) $iterations;

		switch (strtolower($this->type))
		{
			case 'sha256':
			case 'sha512':
				$salt = $this->sha($salt, $iterations);
			break;
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

		// Truncate salt to 22 characters
		$salt = substr($salt, 0, 22);

		if ( ! $iterations)
		{
			if ($this->iterations)
			{
				// Use configured iterations
				$iterations = $this->iterations;
			}
			else
			{
				// Default to cost of 12
				$iterations = 12;
			}
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
	 * @return string
	 */
	protected function sha($salt = NULL, $iterations = NULL)
	{
		if ( ! $salt)
		{
			$salt = Text::random('alnum', 16);
		}

		// Truncate salt to 16 chars
		$salt = substr($salt, 0, 16);

		if ( ! $iterations)
		{
			if ($this->iterations)
			{
				// Use configured iterations
				$iterations = $this->iterations;
			}
			else
			{
				// Default to 5000 iterations
				$iterations = 5000;
			}
		}

		// Normalize the range
		$iterations = min(99999999, max($iterations, 1000));

		if (substr($this->type, -3) === '256')
		{
			// SHA256
			$prefix = '$5$';
		}
		else
		{
			// SHA512
			$prefix = '$6$';
		}

		return $prefix.'rounds='.$iterations.'$'.$salt.'$';
	}

	public function check($password, $hash, $salt = NULL, $iterations = NULL)
	{
		switch (strtolower($this->type))
		{
			case 'sha256':
			case 'sha512':
				// $5|6$ (3) rounds=<iterations> $ (1) <salt> (16)
				preg_match('/^\$(?:5|6)\$rounds=(\d+)\$(.{16})/D', $hash, $matches);
			break;
			default:
				// $2a$ (4) 00 (2) $ (1) <salt> (22)
				preg_match('/^\$2a\$(\d{2})\$(.{22})/D', $hash, $matches);
			break;
		}

		// Extract the iterations and salt from the hash
		list($_, $iterations, $salt) = $matches;

		return parent::check($password, $hash, $salt, $iterations);
	}

} // End Bonafide Mechanism Crypt
