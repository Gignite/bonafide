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

	public static $default = 'default';

	public static $instances = array();

	public static function instance($name = NULL, array $config = NULL)
	{
		if ($name === NULL)
		{
			$name = Auth::$default;
		}

		if ( ! isset(Auth::$instances[$name]))
		{
			$configuration = Arr::get(Kohana::config('auth'), $name, array());

			if ($config)
			{
				$configuration = $config + $configuration;
			}

			Auth::$instances[$name] = new Auth($configuration);
		}

		return Auth::$instances[$name];
	}

	public $config = array();

	public function __construct(array $config)
	{
		$this->config = $config;
	}

} // End Bonafide_Auth
