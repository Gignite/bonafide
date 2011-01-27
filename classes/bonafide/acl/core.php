<?php defined('SYSPATH') or die('No direct script access.');
/**
 * Bonafide is a flexible authentication system for the Kohana Framework.
 *
 * @package    Bona Fide
 * @category   Base
 * @author     Woody Gilk <woody.gilk@kohanaframework.org>
 * @copyright  (c) 2011 Woody Gilk
 * @license    MIT
 */
class Bonafide_ACL_Core {

	// Wildcard for all types
	const WILDCARD = '*';

	/**
	 * Create a new access control list.
	 *
	 * @param   array  configuration
	 * @return  Bonafide_ACL
	 */
	public static function factory(array $config = NULL)
	{
		return new Bonafide_ACL($config);
	}

	/**
	 * @var  string  instance name
	 */
	public $name;

	/**
	 * @var  array  ACL roles
	 */
	protected $_roles = array();

	/**
	 * @var  array  ACL resources
	 */
	protected $_resources = array();

	/**
	 * @var  array  ACL permissions
	 */
	protected $_permissions = array();

	/**
	 * Load configuration parameters.
	 *
	 * @param  array  configuration
	 */
	public function __construct(array $config = NULL)
	{
		if (isset($config['name']))
		{
			$this->name = (string) $config['name'];
		}
	}

	/**
	 * Add a new role and set the parent role(s).
	 *
	 * @param   string  role name
	 * @param   string  inherited parent role or array of roles
	 * @return  Bonafide_ACL
	 */
	public function role($name, $parents = NULL)
	{
		if ( ! is_array($parents))
		{
			if ($parents === NULL)
			{
				$parents = array();
			}
			else
			{
				$parents = array($parents);
			}
		}

		if ($parents)
		{
			// Create a mirrored array
			$parents = array_combine($parents, $parents);
		}

		$this->_roles[$name] = $parents;

		return $this;
	}

	/**
	 * Get all inherited roles for a single role.
	 *
	 * @param   string  role name
	 * @return  array
	 */
	public function roles($name)
	{
		// Add this role to the set
		$roles = array($name => $name);

		if (isset($this->_roles[$name]))
		{
			foreach ($this->_roles[$name] as $role)
			{
				// Inherit parents
				$roles = array_merge($roles, $this->roles($role));
			}
		}

		return $roles;
	}

	/**
	 * Add a new resource and set the parent resource(s).
	 *
	 * @param   string  resource name
	 * @param   string  inherited parent resource or array of resources
	 * @return  Bonafide_ACL
	 */
	public function resource($name, $parents = NULL)
	{
		if ( ! is_array($parents))
		{
			if ( ! $parents)
			{
				$parents = array();
			}
			else
			{
				$parents = array($parents);
			}
		}

		if ($parents)
		{
			// Make the parents a mirrored array
			$parents = array_combine($parents, $parents);
		}

		$this->_resources[$name] = $parents;

		return $this;
	}

	/**
	 * Get all inherited resources for a single resource.
	 *
	 * @param   string  resource name
	 * @return  array
	 */
	public function resources($name)
	{
		// Add this resource to the set
		$resources = array($name => $name);

		if (isset($this->_resources[$name]))
		{
			foreach ($this->_resources[$name] as $resource)
			{
				// Inherit parents
				$resources = array_merge($resources, $this->resources($resource));
			}
		}

		return $resources;
	}

	/**
	 * Add a permission for a role, setting the actions, resources, and
	 * access type (allow, deny).
	 *
	 * @param   string   role name
	 * @param   mixed    single action or array of actions
	 * @param   mixed    single resource or array of resources
	 * @param   boolean  is the role allowed access?
	 * @return  Bonafide_ACL
	 */
	public function permission($role, $actions, $resources, $access)
	{
		if ( ! $role)
		{
			$role = Bonafide_ACL::WILDCARD;
		}

		if ( ! is_array($actions))
		{
			if ( ! $actions)
			{
				$actions = array(Bonafide_ACL::WILDCARD);
			}
			else
			{
				$actions = array($actions);
			}
		}

		if ( ! is_array($resources))
		{
			if ( ! $resources)
			{
				$resources = array(Bonafide_ACL::WILDCARD);
			}
			else
			{
				$resources = array($resources);
			}
		}

		foreach ($actions as $action)
		{
			foreach ($resources as $resource)
			{
				$this->_permissions[$role][$action][$resource] = (bool) $access;
			}
		}

		return $this;
	}

	/**
	 * Add "allow" access to a role.
	 *
	 * @param   string   role name
	 * @param   mixed    single action or array of actions
	 * @param   mixed    single resource or array of resources
	 * @return  Bonafide_ACL
	 */
	public function allow($role, $action = NULL, $resource = NULL)
	{
		return $this->permission($role, $action, $resource, TRUE);
	}

	/**
	 * Add "deny" access to a role.
	 *
	 * @param   string   role name
	 * @param   mixed    single action or array of actions
	 * @param   mixed    single resource or array of resources
	 * @return  Bonafide_ACL
	 */
	public function deny($role, $action = NULL, $resource = NULL)
	{
		return $this->permission($role, $action, $resource, FALSE);
	}

	/**
	 * Check if a role is allowed is allowed to perform an action on a resource.
	 * Recursively checks all inherited roles and resources.
	 *
	 * @param   string   role name
	 * @param   string   action type
	 * @param   string   resource name
	 * @return  boolean
	 */
	public function allowed($role, $action = NULL, $resource = NULL)
	{
		// Start searching with wildcards
		$roles = $actions = $resources = array(Bonafide_ACL::WILDCARD => Bonafide_ACL::WILDCARD);

		// All all inherited roles for this role
		$roles += $this->roles($role);

		if ($action)
		{
			// Search specific actions
			$actions += array($action => $action);
		}

		if ($resource)
		{
			// Search specific resources
			$resources += $this->resources($resource);
		}

		foreach ($roles as $role)
		{
			foreach ($actions as $action)
			{
				foreach ($resources as $resource)
				{
					if (isset($this->_permissions[$role][$action][$resource]))
					{
						// Check the entire matrix, starting with the wildcard
						return ($this->_permissions[$role][$action][$resource] === TRUE);
					}
				}
			}
		}

		return FALSE;
	}

	/**
	 * Check if a role is allowed is denied to perform an action on a resource.
	 * Recursively checks all inherited roles and resources.
	 *
	 * @param   string   role name
	 * @param   string   action type
	 * @param   string   resource name
	 * @return  boolean
	 */
	public function denied($role, $action = NULL, $resource = NULL)
	{
		return ! $this->allowed($role, $action, $resource);
	}

} // End Bonafide_ACL
