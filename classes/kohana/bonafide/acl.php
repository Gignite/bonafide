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
abstract class Kohana_Bonafide_ACL {

	/**
	 * @var  string  name for "any" entity
	 */
	const WILDCARD = '*';

	/**
	 * @var  string  name for "role" entity
	 */
	const ROLE = 'role';

	/**
	 * @var  string  name for "action" entity
	 */
	const ACTION = 'action';

	/**
	 * @var  string  name for "resource" entity
	 */
	const RESOURCE = 'resource';

	/**
	 * @var  string  default instance name
	 */
	public static $default = 'default';

	/**
	 * @var  array  ACL instances, by name
	 */
	public static $instances = array();

	/**
	 * Create an access control list instance.
	 *
	 *     $acl = Bonafide_ACL::instance($name, $config);
	 *
	 * @param   string  instance name
	 * @param   array   configuration
	 * @return  Bonafide_ACL
	 */
	public static function instance($name = NULL, array $config = NULL)
	{
		if ( ! $name)
		{
			// Use the default instance name
			$name = Bonafide_ACL::$default;
		}

		if ( ! isset(Bonafide_ACL::$instances[$name]))
		{
			// Register the instance
			Bonafide_ACL::$instances[$name] = new Bonafide_ACL($config);

			// Forcibly set the instance name
			Bonafide_ACL::$instances[$name]->_instance = $name;
		}

		return Bonafide_ACL::$instances[$name];
	}

	/**
	 * @var  string  instance name for this list
	 */
	protected $_instance = '';

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
	 *     $acl = new Bonafide_ACL($config);
	 *
	 * @param   array  configuration
	 * @return  void
	 */
	public function __construct(array $config = NULL)
	{
		// Nothing, yet
	}

	/**
	 * Add this object back to global instances when unserialized.
	 *
	 *     unserialize($acl);
	 *
	 * @return  void
	 */
	public function __wakeup()
	{
		if ($this->_instance)
		{
			// This object is used as an instance
			Bonafide_ACL::$instances[$this->_instance] = $this;
		}
	}

	/**
	 * Get the instance name of this access list.
	 *
	 *     $name = $acl->name();
	 *
	 * @return  string
	 */
	public function name()
	{
		return $this->_instance();
	}

	/**
	 * Add a new role, optionally copying permissions from other roles.
	 *
	 *     // Add a "guest" role
	 *     $acl->role('guest');
	 *
	 *     // Add a "member" role that inherits from "guest"
	 *     $acl->role('member', 'guest');
	 *
	 *     // Add a "admin" role
	 *     $acl->role('admin');
	 *
	 * @param   string  role name
	 * @param   mixed   copied role name or array of roles
	 * @return  Bonafide_ACL
	 */
	public function role($name, $parents = NULL)
	{
		// Add this role
		$this->_roles[$name] = $name;

		// Initialize permissions array
		$this->_permissions[$name] = array();

		if ($parents)
		{
			if ( ! is_array($parents))
			{
				// Force parents to be an array
				$parents = array($parents);
			}

			foreach ($parents as $parent)
			{
				// Copy parent permissions to this role
				$this->_permissions[$name] = array_merge($this->_permissions[$name], $this->_permissions[$parent]);
			}
		}

		return $this;
	}

	/**
	 * Add a new resource, optionally copying permissions from other resources.
	 *
	 *     // Add a "users" resource
	 *     $acl->resource('users');
	 *
	 *     // Add a "news" resource
	 *     $acl->resource('news');
	 *
	 *     // Add a "latest" resource with inherits from "news"
	 *     $acl->resource('latest', 'news');
	 *
	 * @param   string  resource name
	 * @param   mixed   single action or array of actions
	 * @return  Bonafide_ACL
	 */
	public function resource($name, $actions)
	{
		if ( ! $name OR ! $actions)
		{
			throw new Bonafide_Exception('All resources must have a name and at least one action');
		}

		if ($actions)
		{
			if ( ! is_array($actions))
			{
				// Only one action, make it an array
				$actions = array($actions);
			}

			// Mirror the array keys and values
			$actions = array_combine($actions, $actions);
		}
		else
		{
			// No actions defined
			$actions = array();
		}

		// Sort alphabetically
		ksort($actions, SORT_LOCALE_STRING);

		// Create the resource
		$this->_resources[$name] = $actions;

		return $this;
	}

	/**
	 * Get an associative array of all roles.
	 *
	 *     // Get all defined roles
	 *     $roles = $acl->roles();
	 *
	 * [!!] Unlike actions and resources, roles are not sorted!
	 *
	 * @return  array
	 */
	public function roles()
	{
		// Get all defined roles
		$roles = array_keys($this->_roles);

		if ($roles)
		{
			// Create a mirrored array
			$roles = array_combine($roles, $roles);
		}

		return $roles;
	}

	/**
	 * Get a sorted associative array of all actions for a set of resources.
	 *
	 *     // Get all possible actions for "news"
	 *     $actions = $acl->actions('news');
	 *
	 *     // Get all possible actions for all resources
	 *     $actions = $acl->actions();
	 *
	 * @param   mixed    single resource or array of resources
	 * @return  array
	 */
	public function actions($resources = NULL)
	{
		if ($resources)
		{
			if ( ! is_array($resources))
			{
				// Resources must always be an array
				$resources = array($resources);
			}
		}
		else
		{
			// Use all resources
			$resources = $this->resources();
		}

		$actions = array();

		foreach ($resources as $resource)
		{
			if (isset($this->_resources[$resource]))
			{
				$actions += $this->_resources[$resource];
			}
		}

		ksort($actions, SORT_LOCALE_STRING);

		return $actions;
	}

	/**
	 * Get a sorted associative array of all resources.
	 *
	 *     // Get all defined resources
	 *     $resources = $acl->resources();
	 *
	 * @return  array
	 */
	public function resources()
	{
		// Get all defined resources
		$resources = array_keys($this->_resources);

		if ($resources)
		{
			// Create a mirrored array
			$resources = array_combine($resources, $resources);

			// Sort alphabetically
			ksort($resources, SORT_LOCALE_STRING);
		}

		return $resources;
	}

	/**
	 * Check if an action can be performed on a resource.
	 *
	 *     // Does "news" have an "edit" action?
	 *     if ($acl->can('edit', 'news')) {}
	 *
	 *     // Does "article" have a "comment" action?
	 *     if ($acl->can('comment', 'article')) {}
	 *
	 * @param   string   action name
	 * @param   string   resource name
	 * @return  boolean
	 */
	public function can($action, $resource)
	{
		if ($action === Bonafide_ACL::WILDCARD OR $resource === Bonafide_ACL::WILDCARD)
		{
			// Anything is possible.
			return TRUE;
		}

		if ($actions = $this->actions($resource))
		{
			// Does the action exist?
			return isset($actions[$action]);
		}

		return FALSE;
	}

	/**
	 * Check if an entity exists.
	 *
	 *     // Check if a role called "admin" exists
	 *     if ($acl->has(Bonafide_ACL::ROLE, 'admin')) { ... }
	 *
	 *     // Check if an action call "archive"
	 *     if ($acl->has(Bonafide_ACL::ACTION, 'blah')) { ... }
	 *
	 * [!!] The entity constant (`Bonafide_ACL::ROLE`) or name (`'role'`) can
	 * be used interchangably. Using constants will be slightly faster.
	 *
	 * @param   string  entity type
	 * @param   string  entity name
	 * @return  boolean
	 */
	public function has($entity, $name)
	{
		switch ($entity)
		{
			case Bonafide_ACL::ROLE:
				$all = $this->roles();
			break;
			case Bonafide_ACL::ACTION:
				$all = $this->actions();
			break;
			case Bonafide_ACL::RESOURCES:
				$all = $this->resources();
			break;
			default:
				throw new InvalidArgumentException('Unknown entity type: '.$type);
			break;
		}

		return isset($all[$name]);
	}

	/**
	 * Add "allow" access to a role.
	 *
	 *     // Allow "guest" to "view" everything
	 *     $acl->allow('guest', 'view');
	 *
	 *     // Allow "member" to "comment" on "news"
	 *     $acl->allow('member', 'comment', 'news');
	 *
	 *     // Allow "admin" to do anything
	 *     $acl->allow('admin');
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
	 *     // Deny "guest" to do anything with "latest"
	 *     $acl->deny('guest', NULL, 'latest');
	 *
	 *     // Deny "member" to "edit" the "news"
	 *     $acl->deny('member', 'edit', 'news');
	 *
	 * [!!] By default, everything in an access control list is denied. It is
	 * not necessary to explicitly deny actions except when an inherited role
	 * is allowed access.
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
	 * Add a permission for a role, setting the actions, resources, and
	 * access type (allow, deny).
	 *
	 *     // Allow "admin" to access everything
	 *     $acl->permission('admin', NULL, NULL, TRUE);
	 *
	 * [!!] It is not recommended to use this method directly. Instead, use
	 * the [Bonafide_ACL::allow] and [Bonafide_ACL::deny] methods.
	 *
	 * @param   mixed    single role or array of roles
	 * @param   mixed    single action or array of actions
	 * @param   mixed    single resource or array of resources
	 * @param   boolean  is the role allowed access?
	 * @return  Bonafide_ACL
	 */
	public function permission($roles, $actions, $resources, $access)
	{
		$entities = array('roles', 'actions', 'resources');

		foreach ($entities as $entity)
		{
			if ($$entity)
			{
				if ( ! is_array($$entity))
				{
					// Make the entity into an array
					$$entity = array($$entity);
				}
			}
			else
			{
				// Modify "any" entity.
				$$entity = array(Bonafide_ACL::WILDCARD);
			}
		}

		foreach ($roles as $role)
		{
			foreach ($actions as $action)
			{
				foreach ($resources as $resource)
				{
					if ($this->can($action, $resource))
					{
						// Set this roles ability to perform this action on this resource
						$this->_permissions[$role][$action][$resource] = (bool) $access;
					}
				}
			}
		}

		return $this;
	}

	/**
	 * Check if a role is allowed is allowed to perform an action on a resource.
	 * Recursively checks all inherited roles and resources.
	 *
	 *     // Is "guest" allowed to "commment" the "news"?
	 *     $acl->allowed('guest', 'commment', 'news'); // FALSE
	 *
	 *     // Is "member" allowed to "commment" the "news"?
	 *     $acl->allowed('member', 'commment', 'news'); // TRUE
	 *
	 *     // Is "member" allowed to "edit" the "latest"?
	 *     $acl->allowed('member', 'edit', 'latest'); // FALSE
	 *
	 *     // Is "admin" allowed to "edit" the "news"?
	 *     $acl->allowed('admin', 'edit', 'news'); // TRUE
	 *
	 * @param   string   role name
	 * @param   string   action type
	 * @param   string   resource name
	 * @return  boolean
	 */
	public function allowed($role, $action, $resource)
	{
		// Search wildcards
		$roles = $actions = $resources = array(Bonafide_ACL::WILDCARD);

		// A specific role or any role
		array_push($roles, $role);

		if ($action)
		{
			// Do a specific action
			array_push($actions, $action);
		}

		if ($resource)
		{
			// On a specific resource or any resource
			array_push($resources, $resource);
		}

		$allow = FALSE;

		foreach ($roles as $role)
		{
			foreach ($actions as $action)
			{
				foreach ($resources as $resource)
				{
					if (isset($this->_permissions[$role][$action][$resource]))
					{
						// Can this role perform this action on this resource?
						$allow = $this->_permissions[$role][$action][$resource];
					}
				}
			}
		}

		return $allow;
	}

	/**
	 * Check if a role is allowed is denied to perform an action on a resource.
	 * Recursively checks all inherited roles and resources.
	 *
	 *     // Is "admin" denied to "view" the "latest"?
	 *     $acl->denied('admin', 'view', 'news'); // FALSE
	 *
	 *     // Is "guest" denied to "view" the "latest"?
	 *     $acl->denied('guest', 'view', 'latest'); // TRUE
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

	/**
	 * Get a complete matrix of possible actions and resources.
	 *
	 * An ACL matrix is visually described as:
	 *
	 *              action  action  action  action
	 *     resource   x       x       x       x
	 *     resource                           x
	 *     resource   x               x       x
	 *     resource           x       x       x
	 *
	 * All possible actions are listed across the top, and all resources are
	 * listed down the side. Any action that is possible on the resource is
	 * marked with an "x" and an empty space represents an action that does not
	 * exist for the resource.
	 *
	 * This matrix can be checked against a role to display allowed actions:
	 *
	 *      (role)  action  action  action  action
	 *     resource   x       o       o       x
	 *     resource                           x
	 *     resource   o               x       x
	 *     resource           o       o       x
	 *
	 * In this matrix, allowed actions are represented by an "x" and denied
	 * actions are represented by an "o" and empty space represents an action
	 * that does not exist for the resource.
	 *
	 * @return   array
	 */
	public function matrix($resources = NULL)
	{
		if ($resources)
		{
			if ( ! is_array($resources))
			{
				// Resources must always be an array
				$resources = array($resources);
			}
		}
		else
		{
			// Use all resources
			$resources = $this->resources();
		}

		// Get all actions for these resources
		$actions = $this->actions($resources);

		// Start the matrix
		$matrix = array();

		foreach ($actions as $action)
		{
			foreach ($resources as $resource)
			{
				// Is it possible to perform "action" on "resource"?
				$matrix[$resource][$action] = $this->can($action, $resource);
			}
		}

		return $matrix;
	}

} // End Bonafide_ACL
