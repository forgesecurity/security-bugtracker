<?php if ( !defined( 'WI_VERSION' ) ) die( -1 ); ?>

<h2>Security Plugins Configuration</h2>

<div class="toolbar">
<?php $toolBar->render() ?>
</div>

<div style="float: right">
<?php
    echo $this->imageAndTextLink( $this->mergeQueryString( '/client/index.php?security=1&install=yes' ), '/common/images/edit-modify-16.png', $this->tr( 'Install Plugin' ) );
    echo ' | ' . $this->imageAndTextLink( $this->mergeQueryString( '/client/index.php?security=1&install=no' ), '/common/images/edit-delete-16.png', $this->tr( 'Delete Plugin' ) );
?>
</div>


<?php if ( $install == "yes" ): ?>
<div class="comment-text">install yes</div>
<?php elseif ( $install == "no" ): ?>
<div class="comment-text">install no</div>
<?php else: ?>
<div class="comment-text">install yes or no</div>
<?php endif ?>
