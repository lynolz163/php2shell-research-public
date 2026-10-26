<?php
// php2shell-research lab target. Multipart body parsing (rfc1867) happens in
// request startup BEFORE this script runs, so any PHP file works as a target.
header('Content-Type: text/plain; charset=utf-8');
printf("PHP %s (%s)\n", PHP_VERSION, php_sapi_name());
foreach ([
    'memory_limit', 'post_max_size', 'upload_max_filesize',
    'max_file_uploads', 'max_input_nesting_level',
    'session.upload_progress.enabled', 'session.upload_progress.min_freq',
] as $k) {
    printf("%s = %s\n", $k, ini_get($k) === false ? '(not set)' : ini_get($k));
}
echo "session_id = " . session_id() . "\n";
if (!empty($_SESSION)) {
    echo "_SESSION = ";
    var_export($_SESSION);
    echo "\n";
}
