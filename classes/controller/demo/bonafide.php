<?php defined('SYSPATH') or die('No direct script access.');

class Controller_Demo_Bonafide extends Controller_Demo {

	/**
	 * @var  object  access control list
	 */
	protected $acl;

	public function before()
	{
		$this->acl = Bonafide::acl('blog')
			// Blog has posts and comments
			->resource('post', array('add', 'publish', 'delete', 'edit', 'view'))
			->resource('comment', array('add', 'approve', 'delete', 'view'))
			// Guest
			->role('guest')
				// Can view anything; add comments
				->allow('guest', 'view')
				->allow('guest', 'add', 'comment')
			// Author, has all the guest roles
			->role('author', 'guest')
				// Can also add posts; approve comments
				->allow('author', 'add', 'post')
				->allow('author', 'approve', 'comment')
			// Publisher, has all the author roles
			->role('publisher', 'author')
				// Can also publish anything; edit posts; delete comments
				->allow('publisher', 'publish')
				->allow('publisher', 'edit', 'post')
				->allow('publisher', 'delete', 'comment')
			// Administrator, not inherited
			->role('admin')
				// Can do anything, except publish
				->allow('admin')
				->deny('admin', 'publish')
				;

		return parent::before();
	}

	public function demo_acl()
	{
		$this->content = View::factory('demo/bonafide/acl/debug')
			->set('matrix', $this->request->url(array('demo' => 'acl_matrix')))
			// Add roles and selected role
			->set('roles', $this->acl->roles())
			->bind('role', $role)
			// Add actions and selected action
			->set('actions', $this->acl->actions())
			->bind('action', $action)
			// Add resources and selected resource
			->set('resources', $this->acl->resources())
			->bind('resource', $resource)
			// Can this action be performed?
			->bind('can', $can)
			// Is this action allowed?
			->bind('allowed', $allowed)
			;

		if (Request::$method === 'POST')
		{
			// Get role, action, and resource from POST data
			list($role, $action, $resource) = array_values(Arr::extract($_POST, array('role', 'action', 'resource')));

			// Does this resource have the action?
			$can = $this->acl->can($action, $resource);

			// Is this action allowed?
			$allowed = $this->acl->allowed($role, $action, $resource);
		}
	}

	public function demo_acl_matrix()
	{
		$this->content = View::factory('demo/bonafide/acl')
			->set('debugger', $this->request->url(array('action' => FALSE)))
			->bind('acl', $this->acl)
			->set('resources', Arr::get($_GET, 'resources'))
			;
	}

} // End Bonafide
