<h1>ACL Debugger</h1>

<p>Something seem off? Check the <?php echo HTML::anchor($matrix, 'full matrix') ?>.</p>

<?php echo Form::open(Request::current()) ?>
<p>
	Is <?php echo Form::select('role', Arr::unshift($roles, '', '-- any'), $role) ?>
	allowed to <?php echo Form::select('action', Arr::unshift($actions, '', '-- any'), $action) ?>
	a <?php echo Form::select('resource', Arr::unshift($resources, '', '-- any'), $resource) ?>
	?
	<button type="submit">Test It!</button>
</p>
<?php echo Form::close() ?>

<?php if (is_bool($allowed)) include Kohana::find_file('views/demo', 'bonafide/acl/check') ?>
