#!/usr/bin/env python3
"""Read-only PHP-FPM build/config check for CVE-2026-109618.

This utility inspects an existing local FPM container or a cached local image.
It only runs php-fpm -v, php-fpm -i, uname -m, and read-only package queries;
it sends no HTTP request and no PoC.
"""
import argparse
import datetime as dt
import hashlib
from html.parser import HTMLParser
import json
import os
import re
import subprocess
import sys
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXED = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}
EOL_SOURCE_BACKPORTS = {
    (7, 4): {
        "branch": "PHP-7.4-CVE-2026-109618-109619",
        "commit": "712e60f9edfd03f0960fc4fc3c2c375f42b90aa2",
    },
    (8, 0): {
        "branch": "PHP-8.0-CVE-2026-109618-109619",
        "commit": "82f8f31b16a035c1b67cc253e79f7cc288f4cc20",
    },
    (8, 1): {
        "branch": "PHP-8.1-CVE-2026-109618-109619",
        "commit": "1d7dec178a094e6e75b229ce22754045f8c6070a",
    },
}
DIRECTIVE = "memory_hard_limit_percent"
PLATFORM_ALIASES = {
    "amd64": "linux/amd64",
    "x86_64": "linux/amd64",
    "linux/amd64": "linux/amd64",
    "arm64": "linux/arm64",
    "aarch64": "linux/arm64",
    "linux/arm64": "linux/arm64",
}
UNAME_TO_PLATFORM = {
    "x86_64": "linux/amd64",
    "amd64": "linux/amd64",
    "aarch64": "linux/arm64",
    "arm64": "linux/arm64",
}
INI_NAMES = (
    "memory_limit",
    "post_max_size",
    "max_input_vars",
    "enable_post_data_reading",
)
SOURCES = [
    "https://www.php.net/manual/en/ini.core.php",
    "https://www.php.net/ChangeLog-8.php",
    "https://www.php.net/archive/2026.php",
]
PROVENANCE_SCRIPT = r"""set +e
os_id=unknown
os_version=unknown
if [ -r /etc/os-release ]; then
  while IFS= read -r line; do
    case "$line" in
      ID=*) os_id=${line#ID=}; os_id=${os_id#\"}; os_id=${os_id%\"} ;;
      VERSION_ID=*) os_version=${line#VERSION_ID=}; os_version=${os_version#\"}; os_version=${os_version%\"} ;;
    esac
  done < /etc/os-release
fi
fpm_path=$(command -v php-fpm 2>/dev/null)
printf 'OS_ID=%s\nOS_VERSION_ID=%s\nPHP_FPM_PATH=%s\n' "$os_id" "$os_version" "${fpm_path:-not_found}"
if [ -z "$fpm_path" ]; then
  printf 'PACKAGE_MANAGER=unknown\nPACKAGE_STATUS=fpm_binary_not_found\n'
elif command -v rpm >/dev/null 2>&1; then
  package=$(rpm -qf --qf '%{NAME}=%{VERSION}-%{RELEASE}.%{ARCH}' "$fpm_path" 2>/dev/null)
  if [ -n "$package" ]; then
    printf 'PACKAGE_MANAGER=rpm\nPACKAGE_STATUS=found\nPACKAGE=%s\n' "$package"
  else
    printf 'PACKAGE_MANAGER=rpm\nPACKAGE_STATUS=owner_not_found\n'
  fi
elif command -v dpkg-query >/dev/null 2>&1; then
  owner_line=$(dpkg-query -S "$fpm_path" 2>/dev/null)
  case "$owner_line" in *:*) owner=${owner_line%%:*} ;; esac
  if [ -n "$owner" ]; then
    package_version=$(dpkg-query -W -f='${Version}' "$owner" 2>/dev/null)
    printf 'PACKAGE_MANAGER=dpkg\nPACKAGE_STATUS=found\nPACKAGE=%s\nPACKAGE_VERSION=%s\n' "$owner" "$package_version"
  else
    printf 'PACKAGE_MANAGER=dpkg\nPACKAGE_STATUS=owner_not_found\n'
  fi
elif command -v apk >/dev/null 2>&1; then
  owner_line=$(apk info --who-owns "$fpm_path" 2>/dev/null)
  case "$owner_line" in *" is owned by "*) package=${owner_line##* is owned by } ;; esac
  if [ -n "$package" ]; then
    package_version=$(apk info -v "$package" 2>/dev/null)
    printf 'PACKAGE_MANAGER=apk\nPACKAGE_STATUS=found\nPACKAGE=%s\nPACKAGE_VERSION=%s\n' "$package" "$package_version"
  else
    printf 'PACKAGE_MANAGER=apk\nPACKAGE_STATUS=owner_not_found\n'
  fi
else
  printf 'PACKAGE_MANAGER=none\nPACKAGE_STATUS=package_manager_not_found\n'
fi
exit 0"""


def now_utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def normalize_platform(value):
    """Normalize Docker and uname spellings without guessing unknown values."""
    if value is None:
        return None
    normalized = PLATFORM_ALIASES.get(value.strip().lower())
    if normalized is None:
        raise argparse.ArgumentTypeError(
            "platform must be linux/amd64, linux/arm64, x86_64, amd64, "
            "aarch64, or arm64"
        )
    return normalized


def run_bounded(command, timeout=20):
    started = now_utc()
    proc = subprocess.Popen(command, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    record = {"command": command, "pid": proc.pid,
              "started_at_utc": started, "timeout_seconds": timeout}
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        record.update({"exit_code": proc.returncode, "stdout": stdout,
                       "stderr": stderr, "timed_out": False})
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate(timeout=5)
        record.update({"exit_code": proc.returncode, "stdout": stdout,
                       "stderr": stderr, "timed_out": True})
    record["finished_at_utc"] = now_utc()
    return record


class PlainText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []

    def handle_data(self, data):
        value = " ".join(data.split())
        if value:
            self.parts.append(value)


def plain_phpinfo(source):
    parser = PlainText()
    parser.feed(source)
    return " ".join(parser.parts)


def version_tuple(text):
    match = re.search(r"\bPHP\s+(\d+)\.(\d+)\.(\d+)\b", text)
    return tuple(int(part) for part in match.groups()) if match else None


def release_status(version):
    if not version:
        return "unknown", None
    fixed = FIXED.get(version[:2])
    if fixed:
        if version < fixed:
            return "affected_release_range", ".".join(map(str, fixed))
        return "at_or_after_fixed_release", ".".join(map(str, fixed))
    if version[0] < 8 or (version[0] == 8 and version[1] <= 1):
        return "eol_vendor_backport_status_unknown", None
    return "unmapped_release_family", None


def official_eol_source_backport(version):
    if not version or not (version[0] < 8 or (version[0] == 8 and version[1] <= 1)):
        return None
    record = EOL_SOURCE_BACKPORTS.get(version[:2])
    if not record:
        return {
            "availability": "not_published_by_php_project_for_this_branch",
            "scope": "PHP's official notice names source backports for 7.4, 8.0, and 8.1 only.",
        }
    return {
        "availability": "official_source_backport_available",
        "branch": record["branch"],
        "commit": record["commit"],
        "patch_url": "https://github.com/php/php-src/commit/%s.patch" % record["commit"],
        "scope": "Minimal source-only mitigation; this version string does not prove the running build contains it.",
    }


def collect_image(image, timeout, platform=None):
    metadata = run_bounded([
        "docker", "image", "inspect", "--format",
        "{{.Id}} {{.Os}}/{{.Architecture}}", image], timeout=10)
    suffix = uuid.uuid4().hex[:8]
    records = {"image_inspect": metadata, "commands": [],
               "requested_platform": platform or "image_default"}
    records["image_id_arch"] = metadata.get("stdout", "").strip()
    if metadata.get("exit_code") != 0:
        return records
    for label, args in (("version", ["php-fpm", "-v"]),
                        ("info", ["php-fpm", "-i"]),
                        ("architecture", ["uname", "-m"]),
                        ("provenance", ["sh", "-c", PROVENANCE_SCRIPT])):
        name = "fpm-safe-check-%s-%s" % (label, suffix)
        command = ["docker", "run", "--pull=never"]
        if platform:
            command += ["--platform", platform]
        command += ["--rm", "--network", "none", "--name", name, image] + args
        result = run_bounded(command, timeout=timeout)
        result["container_name"] = name
        result["cleanup_method"] = "docker run --rm; exact-name stop attempted only on timeout"
        if result.get("timed_out"):
            stop = run_bounded(["docker", "stop", "--time", "3", name], timeout=8)
            result["timeout_stop"] = stop
        verify = run_bounded(["docker", "inspect", name], timeout=8)
        result["cleanup_verified_absent"] = verify.get("exit_code") != 0
        records["commands"].append({"purpose": label, **result})
    return records


def collect_container(container, timeout):
    inspect = run_bounded([
        "docker", "inspect", "--format",
        "{{.State.Running}}|{{.Config.Image}}|{{.Image}}|{{.Id}}", container],
        timeout=10)
    records = {"container_inspect": inspect, "commands": [],
               "requested_platform": "container_runtime"}
    if inspect.get("exit_code") != 0:
        return records
    parts = inspect.get("stdout", "").strip().split("|", 3)
    records["container_metadata"] = {
        "running": parts[0] == "true" if len(parts) > 0 else False,
        "configured_image": parts[1] if len(parts) > 1 else None,
        "image_id": parts[2] if len(parts) > 2 else None,
        "container_id": parts[3] if len(parts) > 3 else None,
    }
    if not records["container_metadata"]["running"]:
        return records
    for label, args in (("version", ["php-fpm", "-v"]),
                        ("info", ["php-fpm", "-i"]),
                        ("architecture", ["uname", "-m"]),
                        ("provenance", ["sh", "-c", PROVENANCE_SCRIPT])):
        command = ["docker", "exec", container] + args
        result = run_bounded(command, timeout=timeout)
        records["commands"].append({"purpose": label, **result})
    return records


def parse_ini_setting(text, name):
    """Extract the local and master values from flattened phpinfo text."""
    match = re.search(
        r"\b%s\s*=>\s*(.+?)\s*=>\s*(.+?)(?=\s+[A-Za-z_][A-Za-z0-9_.-]*\s*=>|$)"
        % re.escape(name), text, re.I)
    if not match:
        return {"local": None, "master": None}
    return {"local": " ".join(match.group(1).split()),
            "master": " ".join(match.group(2).split())}


def ini_size_bytes(value):
    """Parse common PHP size suffixes for a bounded comparison only."""
    if not value:
        return None
    value = value.strip().lower()
    if value in ("-1", "unlimited"):
        return -1
    match = re.fullmatch(r"([0-9]+)\s*([kmgt]?)", value)
    if not match:
        return None
    amount = int(match.group(1))
    multiplier = {"": 1, "k": 1024, "m": 1024 ** 2,
                  "g": 1024 ** 3, "t": 1024 ** 4}[match.group(2)]
    return amount * multiplier


def platform_from_uname(value):
    return UNAME_TO_PLATFORM.get((value or "").strip().lower())


def summarize(records):
    commands = {item["purpose"]: item for item in records.get("commands", [])}
    version_output = commands.get("version", {}).get("stdout", "")
    info_output = commands.get("info", {}).get("stdout", "")
    architecture_output = commands.get("architecture", {}).get("stdout", "").strip()
    provenance_output = commands.get("provenance", {}).get("stdout", "")
    info_text = plain_phpinfo(info_output)
    ini_settings = {name: parse_ini_setting(info_text, name)
                    for name in INI_NAMES}
    version = version_tuple(version_output)
    if not version:
        version = version_tuple(info_text)
    fpm_sapi = bool(re.search(r"FPM/FastCGI", info_text, re.I))
    marker = DIRECTIVE in info_text
    state, fixed_release = release_status(version)
    source_backport = official_eol_source_backport(version)
    requested_platform = records.get("requested_platform")
    observed_platform = platform_from_uname(architecture_output)
    platform_match = (
        None if requested_platform in (None, "image_default", "container_runtime")
        else observed_platform == requested_platform
    )
    memory_limit = ini_settings["memory_limit"]["local"]
    memory_limit_bytes = ini_size_bytes(memory_limit)
    post_reading = ini_settings["enable_post_data_reading"]["local"]
    if post_reading is None:
        post_parsing = "unknown"
    elif post_reading.lower() in ("on", "1", "true"):
        post_parsing = "enabled"
    elif post_reading.lower() in ("off", "0", "false"):
        post_parsing = "disabled"
    else:
        post_parsing = "unknown"
    if not fpm_sapi:
        assessment = "inconclusive_fpm_sapi_not_confirmed"
    elif platform_match is False:
        assessment = "requested_platform_does_not_match_runtime_architecture"
    elif not marker:
        if state == "at_or_after_fixed_release":
            assessment = "fixed_version_claim_conflicts_with_missing_marker"
        elif state == "eol_vendor_backport_status_unknown":
            assessment = (
                "eol_official_source_backport_available_build_status_unverified"
                if source_backport and source_backport["availability"] == "official_source_backport_available"
                else "eol_official_backport_not_published_for_branch_vendor_status_unverified"
            )
        else:
            assessment = "marker_absent_official_manual_flags_build_as_affected"
    elif state == "affected_release_range":
        assessment = "affected_release_range_marker_present_check_vendor_backport"
    elif state == "at_or_after_fixed_release":
        assessment = "at_or_after_upstream_fixed_release_marker_present"
    elif state == "eol_vendor_backport_status_unknown":
        assessment = "eol_build_marker_present_source_or_vendor_provenance_still_requires_confirmation"
    else:
        assessment = "marker_present_release_family_unmapped"
    return {
        "php_version": ".".join(map(str, version)) if version else None,
        "sapi_fpm_fastcgi_confirmed": fpm_sapi,
        "container_architecture": architecture_output or None,
        "observed_platform": observed_platform,
        "requested_platform": requested_platform,
        "platform_match": platform_match,
        "package_provenance": parse_provenance(provenance_output),
        "ini_settings": ini_settings,
        "precondition_observations": {
            "memory_limit": memory_limit,
            "memory_limit_bytes": memory_limit_bytes,
            "memory_limit_unbounded": memory_limit_bytes == -1,
            "post_data_parsing": post_parsing,
            "post_max_size": ini_settings["post_max_size"]["local"],
            "max_input_vars": ini_settings["max_input_vars"]["local"],
        },
        "memory_hard_limit_percent_registered": marker,
        "release_status": state,
        "fixed_release_for_branch": fixed_release,
        "official_eol_source_backport": source_backport,
        "assessment": assessment,
        "vendor_backport_status": (
            "must_be_verified_with_vendor_or_source_provenance" if state == "eol_vendor_backport_status_unknown"
            else "must_be_verified_with_vendor" if not marker
            else "not_separately_verified"),
        "version_command_output": version_output.strip(),
        "build_provenance": (
            "official_docker_library_php_source_build"
            if "docker-library/php" in version_output else "unclassified"
        ),
        "phpinfo_sha256": hashlib.sha256(info_output.encode()).hexdigest()
        if info_output else None,
        "phpinfo_marker_context": marker_context(info_text),
        "assessment_sources": SOURCES + (
            [source_backport["patch_url"]] if source_backport and source_backport.get("patch_url") else []
        ),
        "proof_limit": (
            "Read-only build/config evidence only; this does not exercise the CVE, "
            "prove application reachability, verify a vendor backport, or establish that a deployment is safe."),
    }


def marker_context(text):
    index = text.find(DIRECTIVE)
    if index < 0:
        return None
    return text[max(0, index - 90):index + 180]


def parse_provenance(output):
    fields = {}
    for line in output.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key.strip().lower()] = value.strip()
    return {
        "os_id": fields.get("os_id"),
        "os_version_id": fields.get("os_version_id"),
        "php_fpm_path": fields.get("php_fpm_path"),
        "package_manager": fields.get("package_manager"),
        "package_status": fields.get("package_status"),
        "package": fields.get("package"),
        "package_version": fields.get("package_version"),
        "scope": "Read-only package ownership metadata; it does not prove the package contains a particular backport.",
    }


def redact_command_output(value):
    """Retain hashes and sizes while avoiding persistence of full phpinfo output."""
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key in ("stdout", "stderr") and isinstance(item, str):
                result[key + "_sha256"] = hashlib.sha256(item.encode()).hexdigest()
                result[key + "_bytes"] = len(item.encode())
                if key == "stderr":
                    result["stderr_nonempty"] = bool(item.strip())
            else:
                result[key] = redact_command_output(item)
        return result
    if isinstance(value, list):
        return [redact_command_output(item) for item in value]
    return value


def failure_analysis(records):
    """Explain collection failures without persisting arbitrary command output."""
    failures = []
    candidates = []
    if records.get("image_inspect"):
        candidates.append(("image_inspect", records["image_inspect"]))
    if records.get("container_inspect"):
        candidates.append(("container_inspect", records["container_inspect"]))
    candidates.extend((item.get("purpose", "unknown_command"), item)
                      for item in records.get("commands", []))

    for purpose, item in candidates:
        if item.get("exit_code") == 0 and not item.get("timed_out"):
            continue
        stderr = (item.get("stderr") or "").lower()
        if item.get("timed_out"):
            cause = "command_exceeded_timeout"
            detail = "The bounded command timed out; inspect exact-container cleanup fields before retrying."
        elif "permission denied" in stderr and "docker.sock" in stderr:
            cause = "docker_daemon_socket_permission_denied"
            detail = "The invoking user could not access the local Docker daemon socket."
        elif "does not provide the specified platform" in stderr:
            cause = "requested_platform_not_present_in_cached_image"
            detail = "The cached image has no variant for the requested platform; no image was pulled."
        elif "no such image" in stderr or "unable to find image" in stderr:
            cause = "image_not_available_locally"
            detail = "The requested image is not available locally and pulling is disabled."
        elif "no such container" in stderr:
            cause = "container_not_available"
            detail = "The specified existing container was not present when inspected."
        else:
            cause = "unclassified_command_failure"
            detail = "The command failed; manual review of the local Docker diagnostic is required."
        failures.append({
            "purpose": purpose,
            "exit_code": item.get("exit_code"),
            "timed_out": bool(item.get("timed_out")),
            "stderr_sha256": hashlib.sha256((item.get("stderr") or "").encode()).hexdigest(),
            "stderr_bytes": len((item.get("stderr") or "").encode()),
            "root_cause": cause,
            "analysis": detail,
            "cleanup_verified_absent": item.get("cleanup_verified_absent"),
            "requires_manual_review": cause == "unclassified_command_failure",
        })

    metadata = records.get("container_metadata") or {}
    if records.get("container_inspect", {}).get("exit_code") == 0 and not metadata.get("running"):
        failures.append({
            "purpose": "container_state",
            "exit_code": None,
            "timed_out": False,
            "root_cause": "existing_container_not_running",
            "analysis": "The named container exists but is stopped; no commands were run inside it.",
            "cleanup_verified_absent": None,
            "requires_manual_review": False,
        })

    expected = 4
    inspected = ((records.get("image_inspect") or records.get("container_inspect") or {})
                 .get("exit_code") == 0)
    complete = inspected and len(records.get("commands", [])) == expected and not failures
    return {"complete": complete, "failures": failures}


def write_check_report(collection, source, started, out):
    failure_report = failure_analysis(collection)
    report = {
        "schema": "php-fpm-cve-2026-109618-safe-check-v1",
        "generated_at_utc": now_utc(),
        "started_at_utc": started,
        "source": source,
        "mode": "read_only_php_fpm_info",
        "commands": redact_command_output(collection),
        "failure_analysis": failure_report,
        "result": summarize(collection),
        "gdb": {
            "status": "not_applicable",
            "reason": "This is a read-only build, architecture, and package-provenance check; no exploit request or memory-corruption path was run.",
        },
    }
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    report["evidence"] = {"json": os.path.abspath(out),
                          "gdb_log": os.path.abspath(out + ".gdb.log")}
    with open(out, "w") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    with open(out + ".gdb.log", "w") as stream:
        stream.write("GDB_NOT_APPLICABLE\n")
        stream.write("reason=read-only PHP-FPM build, architecture, and package-provenance check\n")
        stream.write("no exploit request, memory corruption, or debugger attachment occurred\n")
    required = collection.get("commands") or []
    code = 0 if (report["result"]["php_version"] and
                 report["result"]["sapi_fpm_fastcgi_confirmed"] and
                 report["result"]["container_architecture"] and
                 report["result"]["platform_match"] is not False and
                 failure_report["complete"] and
                 all(item.get("exit_code") == 0 for item in required)) else 2
    return report, code


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_slug(value):
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:80] or "target"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--image", action="append",
                       help="inspect a cached local PHP-FPM image; repeat for a matrix; never pulls")
    group.add_argument("--container", action="append",
                       help="inspect an existing running local FPM container; repeat for a matrix")
    parser.add_argument("--timeout", type=int, default=20,
                        help="per-command timeout in seconds (1-60; default 20)")
    parser.add_argument("--platform", type=normalize_platform,
                        help="image-mode architecture override; Docker never pulls the image")
    parser.add_argument("--out", help="single-target JSON path; defaults under out/version-matrix")
    parser.add_argument("--out-dir", default=os.path.join(ROOT, "out", "version-matrix"),
                        help="directory for per-target reports in a matrix")
    parser.add_argument("--summary-out", help="matrix summary JSON path")
    args = parser.parse_args()
    if args.timeout < 1 or args.timeout > 60:
        parser.error("--timeout must be between 1 and 60 seconds")
    if args.container and args.platform:
        parser.error("--platform applies only to --image")
    targets = ([ ("image", item) for item in (args.image or []) ] if args.image else
               [ ("container", item) for item in (args.container or []) ])
    if len(targets) > 12:
        parser.error("at most 12 targets may be checked in one run")
    if args.timeout > 30 and len(targets) > 1:
        parser.error("matrix mode limits --timeout to 30 seconds per command")
    if args.out and len(targets) != 1:
        parser.error("--out is for a single target; use --out-dir for a matrix")
    if args.summary_out and len(targets) == 1:
        parser.error("--summary-out applies only to a matrix")

    started = now_utc()
    stamp = (dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") +
             "-" + uuid.uuid4().hex[:6])
    os.makedirs(args.out_dir, exist_ok=True)
    reports = []
    exit_codes = []
    for index, (kind, target) in enumerate(targets, 1):
        source = ({"kind": "local_image", "image": target,
                   "platform": args.platform or "image_default"} if kind == "image" else
                  {"kind": "existing_container", "container": target})
        if args.out:
            out = args.out
        else:
            label = safe_slug(kind + "-" + target)
            out = os.path.join(args.out_dir,
                               "safe-fpm-check-%s-%02d-%s.json" % (stamp, index, label))
        target_started = now_utc()
        collection = (collect_image(target, args.timeout, args.platform) if kind == "image"
                      else collect_container(target, args.timeout))
        report, code = write_check_report(collection, source, target_started, out)
        exit_codes.append(code)
        reports.append({
            "source": source,
            "exit_code": code,
            "result": report["result"],
            "failure_analysis": report["failure_analysis"],
            "evidence": {
                "json": report["evidence"]["json"],
                "json_sha256": sha256_file(report["evidence"]["json"]),
                "gdb_log": report["evidence"]["gdb_log"],
                "gdb_log_sha256": sha256_file(report["evidence"]["gdb_log"]),
            },
        })
        if len(targets) == 1:
            print(json.dumps({"result": report["result"], "output": report["evidence"]["json"]}, indent=2))

    if len(targets) > 1:
        counts = {
            "targets": len(reports),
            "collection_complete": sum(1 for item in reports if item["failure_analysis"]["complete"]),
            "incomplete_or_failed": sum(1 for item in reports if not item["failure_analysis"]["complete"]),
            "upstream_affected_release_range": sum(1 for item in reports
                if item["failure_analysis"]["complete"] and
                item["result"]["release_status"] == "affected_release_range"),
            "eol_vendor_status_unknown": sum(1 for item in reports
                if item["failure_analysis"]["complete"] and
                item["result"]["release_status"] == "eol_vendor_backport_status_unknown"),
            "official_eol_source_backport_available": sum(1 for item in reports
                if item["failure_analysis"]["complete"] and
                (item["result"].get("official_eol_source_backport") or {}).get("availability") ==
                "official_source_backport_available"),
            "system_package_owner_identified": sum(1 for item in reports
                if item["failure_analysis"]["complete"] and
                item["result"].get("package_provenance", {}).get("package_status") == "found"),
            "at_or_after_upstream_fixed_release": sum(1 for item in reports
                if item["failure_analysis"]["complete"] and
                item["result"]["release_status"] == "at_or_after_fixed_release"),
            "marker_present": sum(1 for item in reports
                if item["failure_analysis"]["complete"] and
                item["result"]["memory_hard_limit_percent_registered"]),
            "marker_absent": sum(1 for item in reports
                if item["failure_analysis"]["complete"] and
                not item["result"]["memory_hard_limit_percent_registered"]),
            "platform_verified": sum(1 for item in reports
                if item["failure_analysis"]["complete"] and
                item["result"].get("platform_match") is True),
            "platform_mismatch": sum(1 for item in reports
                if item["failure_analysis"]["complete"] and
                item["result"].get("platform_match") is False),
            "post_data_parsing_enabled": sum(1 for item in reports
                if item["failure_analysis"]["complete"] and
                item["result"].get("precondition_observations", {}).get("post_data_parsing") == "enabled"),
        }
        summary_out = args.summary_out or os.path.join(
            args.out_dir, "safe-fpm-matrix-summary-%s.json" % stamp)
        summary = {
            "schema": "php-fpm-cve-2026-109618-safe-matrix-v1",
            "generated_at_utc": now_utc(),
            "started_at_utc": started,
            "mode": "read_only_multi_target_matrix",
            "counts": counts,
            "targets": reports,
            "proof_limit": (
                "Read-only build/config evidence only; this matrix does not exercise the CVE, "
                "prove application reachability, verify vendor backports, or establish that a deployment is safe."),
            "gdb": {"status": "not_applicable", "reason": "Aggregate only; per-target JSON/GDB-N/A pairs are listed above."},
        }
        os.makedirs(os.path.dirname(os.path.abspath(summary_out)), exist_ok=True)
        summary["evidence"] = {
            "json": os.path.abspath(summary_out),
            "gdb_log": os.path.abspath(summary_out + ".gdb.log"),
        }
        with open(summary_out, "w") as stream:
            json.dump(summary, stream, indent=2, sort_keys=True)
            stream.write("\n")
        with open(summary_out + ".gdb.log", "w") as stream:
            stream.write("GDB_NOT_APPLICABLE\naggregate of read-only per-target checks\n")
        print(json.dumps({"counts": counts, "output": os.path.abspath(summary_out)}, indent=2))

    return 0 if all(code == 0 for code in exit_codes) else 2


if __name__ == "__main__":
    sys.exit(main())
