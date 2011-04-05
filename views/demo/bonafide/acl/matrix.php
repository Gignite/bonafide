<table class="acl-matrix">
	<thead>
		<tr>
			<th class="space">&nbsp;</th>
<?php		foreach ($acl->actions($resources) as $action): ?>
			<th class="action"><?php echo HTML::chars($action) ?></th>
<?php		endforeach ?>
		</tr>
	</thead>
	<tbody>
<?php	foreach ($acl->matrix($resources) as $resource => $actions): ?>
		<tr>
			<th class="resource"><?php echo HTML::chars($resource) ?></th>
<?php		foreach ($actions as $action => $used): $input = "{$role}[{$action}][{$resource}]"; ?>
			<td class="<?php echo $used ? 'ability' : 'space' ?>"><?php
				echo $used
					? $acl->allowed($role, $action, $resource) ? '&#10004;' : '&#10007;'
					: '&nbsp;'
			?></td>
<?php		endforeach ?>
		</tr>
<?php	endforeach ?>
	</tbody>
</table>
