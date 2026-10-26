<?php
// Reached only when request startup survived POST parsing.
// If the request aborted during startup this file never executes, which is
// exactly the point: the interesting behaviour happens before user code.
header('Content-Type: text/plain; charset=utf-8');
echo "script_ran\n";
echo "memory_limit=", ini_get('memory_limit'), "\n";
echo "post_max_size=", ini_get('post_max_size'), "\n";
echo "post_keys=", is_array($_POST) ? count($_POST) : -1, "\n";
echo "post_last_key_len=", is_array($_POST) && $_POST ? strlen((string) array_key_last($_POST)) : 0, "\n";
echo "usage=", memory_get_usage(true), "\n";
