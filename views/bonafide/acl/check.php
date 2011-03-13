<h2>Response</h2>
<?php if ( ! $can): ?>
<p><em>It is not possible to <?php echo $action ? HTML::chars($action) : '(any)' ?> a <?php echo $resource ? HTML::chars($resource) : '(any)' ?>.</em></p>
<?php else: ?>
<p>It is<?php if ( ! $allowed): ?> <em>not</em><?php endif ?> allowed.</p>
<?php endif ?>
