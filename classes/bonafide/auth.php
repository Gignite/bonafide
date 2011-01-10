<?php defined('SYSPATH') or die('No direct script access.');
/**
 * Bona Fide is a flexible authentication system for the Kohana Framework.
 *
 * [!!] This module conflicts (intentionally) with the Auth module! Enabling both
 * at the same time will cause unexpected results!
 *
 * @package    Bona Fide
 * @category   Base
 * @author     Woody Gilk <woody.gilk@kohanaframework.org>
 * @copyright  (c) 2011 Woody Gilk
 * @license    MIT
 */
class Bonafide_Auth {

	/**
	 * @param  string  default instance name
	 */
	public static $default = 'default';

	/**
	 * @param  array  Bonafide instances, by name
	 */
	public static $instances = array();

	/**
	 * Get a Bonafide instance. If the instance has not yet been created,
	 * a new instance will be created with the specified configuration.
	 *
	 * @param   string  instance name
	 * @param   array   additional configuration settings
	 * @return  Bonafide
	 */
	public static function instance($name = NULL, array $config = NULL)
	{
		if ($name === NULL)
		{
			$name = Auth::$default;
		}

		if ( ! isset(Auth::$instances[$name]))
		{
			// Load configuration
			$configuration = Arr::get(Kohana::config('bonafide'), $name, array());

			if ($config)
			{
				// Overload default configuration with specified settings
				$configuration = $config + $configuration;
			}

			// Register the instance
			Bonafide::$instances[$name] = new Bonafide($configuration);
		}

		return Bonafide::$instances[$name];
	}

	/**
	 * Load an authentication mechanism.
	 *
	 * @param   string  mechanism name
	 * @param   array   configuration settings
	 * @return  Bonafide_Mechanism
	 */
	public static function mechanism($name, array $config = NULL)
	{
		// Load configuration for this mechanism
		$configuration = Kohana::config('bonafide/'.$name)->as_array();

		if ($config)
		{
			$configuration = $config + $configuration;
		}

		// Build the class name path
		$mechanism = 'Bonafide_Mechanism_'.$name;

		// Register the class for this prefix
		return new $mechanism($configuration);
	}

	/**
	 * @param  array  configuration settings
	 */
	public $config = array();

	/**
	 * @param  array  registered mechanisms
	 */
	public $mechanisms = array();

	/**
	 * Apply configuration and register prefixes.
	 *
	 * @param  array  configuration settings
	 */
	public function __construct(array $config = array())
	{
		$this->config = $config + array(
			'separator' => '~',
		);

		if (isset($this->config['mechanisms']))
		{
			foreach ($this->config['mechanisms'] as $data)
			{
				if (isset($data[1]))
				{
					// Format: array(string $name, array $config)
					list($mechanism, $config) = $data;
				}
				else
				{
					// Supported format: array(string $name)
					// Supported format: string $name
					// Supported format: object $mechanism
					$mechanism = is_array($data) ? array_shift($data) : $data;

					// No configuration has been supplied
					$config = NULL;
				}

				if ( ! is_object($mechanism))
				{
					// Load the mechanism and pass in config
					$mechanism = Bonafide::mechanism($mechanism, $config);
				}

				if ( ! $mechanism instanceof Bonafide_Mechanism)
				{
					throw new Bonafide_Exception('Mechanism class ":class" must extend Bonafide_Mechanism', array(
						':class' => get_class($mechanism),
					));
				}

				// Register the mechanism by its prefix
				$this->mechanisms[$mechanism->prefix] = $mechanism;
			}
		}
	}

	/**
	 * Hash a plaintext password using the current hashing mechanism.
	 *
	 * @param   string   plaintext password
	 * @param   string   appended salt, should be unique per user
	 * @param   integer  number of iterations to run
	 * @return  boolean
	 */
	public function hash($password, $salt = NULL, $iterations = NULL)
	{
		$mechanism = current($this->mechanisms);

		return $mechanism->hash($password, $salt, $iterations);
	}

	/**
	 * Check a user password against the password hash.
	 *
	 * @param   string   plaintext password
	 * @param   string   hashed password, including prefix
	 * @param   string   appended salt, should be unique per user
	 * @param   integer  number of iterations to run
	 * @return  boolean
	 */
	public function check($password, $hash, $salt = NULL, $iterations = NULL)
	{
		// Get a list of all the registered prefixes
		$prefixes = array_keys($this->mechanisms);

		// Quote all the prefixes to make them suitable for regex matching
		$prefixes = array_map('preg_quote', $prefixes);

		if (preg_match('/^(?:'.implode('|', $prefixes).')/uD', $hash, $matches))
		{
			// Get the prefix from the match
			list($prefix) = $matches;
		}
		else
		{
			// This hash has no registered prefix
			$prefix = NULL;
		}

		if ( ! isset($this->mechanisms[$prefix]))
		{
			throw new Bonafide_Exception('Prefix ":prefix" has not been registered, unable to check password', array(
				':prefix' => $prefix,
			));
		}

		// Check the password using this password hash mechanism
		return $this->mechanisms[$prefix]->check($password, $hash, $salt, $iterations);
	}

} // End Bonafide_Auth
