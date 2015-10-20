<?php if ( !defined( 'WI_VERSION' ) ) die( -1 ); ?>

<div class="toolbar">
<?php $toolBar->render() ?>
</div>

<div style="float: right">
<?php
    echo $this->imageAndTextLink( '/client/securityplugin.php?install=yes', '/common/images/edit-modify-16.png', $this->tr( 'Install Plugin' ) );
    echo ' | ' . $this->imageAndTextLink( '/client/securityplugin.php?install=no' , '/common/images/edit-delete-16.png', $this->tr( 'Uninstall Plugin' ) );
?>
</div>


<?php if ( $install == "yes" ): ?>
<div class="comment-text">Installation finished</div>
<?php elseif ( $install == "no" ): ?>
<div class="comment-text">Uninstallation finished</div>
<?php else: ?>
<div class="comment-text">Make your choice</div>
<?php endif ?>
