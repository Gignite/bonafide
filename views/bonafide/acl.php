<h1>ACL Matrix</h1>
<p>Want to run tests? Check the <?php echo HTML::anchor($debugger, 'debugger') ?>.</p>
<?php foreach ($acl->roles() as $role): ?>
<h2><?php echo HTML::chars($role) ?></h2>
<?php include Kohana::find_file('views/bonafide', 'acl/matrix') ?>
<?php endforeach ?>
