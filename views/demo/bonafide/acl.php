<h1>ACL Matrix</h1>
<p>Want to run tests? Check the <?php echo HTML::anchor($debugger, 'debugger') ?>.</p>

<form action="<?php /* form actions are stupid */ ?>" method="get">
<p>Choose what resources to show:</p>
<ul>
<?php foreach ($acl->resources() as $resource): ?>
	<li>
		<label>
			<?php echo Form::checkbox('resources[]', $resource, is_array($resources) ? in_array($resource, $resources) : FALSE) ?>
			<?php echo $resource ?>
		</label>
	</li>
<?php endforeach ?>
</ul>
<button type="submit">Show</button>
</form>

<?php foreach ($acl->roles() as $role): ?>
<h2><?php echo HTML::chars($role) ?></h2>
<?php include Kohana::find_file('views/demo', 'bonafide/acl/matrix') ?>
<?php endforeach ?>
