#!/usr/bin/env python3
"""Read-only consistency audit for saved PHP-FPM version-matrix evidence.

This utility never starts containers, sends HTTP requests, or executes payloads.
It checks that per-run JSON records have paired GDB logs and that the recorded
classification is supported by the evidence fields and log markers.
"""
import argparse
import datetime as dt
import glob
import hashlib
import json
import os
import re
import sys


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def rows_from_document(document):
    if isinstance(document, dict) and document.get("run_id"):
        return [document]
    if isinstance(document, dict) and document.get("schema", "").startswith(
            "php-fpm-cve-2026-109618-safe-check-"):
        return [document]
    # Matrix summaries and indexes are arrays containing copies/references to
    # per-run rows. Count only the authoritative per-run JSON files to avoid
    # double-counting those summaries.
    return []


def safe_log_path(evidence_dir, json_path, row):
    reference = row.get("evidence", {}).get("gdb_log")
    if reference:
        candidate = reference if os.path.isabs(reference) else os.path.join(
            evidence_dir, os.path.basename(reference))
    else:
        candidate = json_path + ".gdb.log"
    root = os.path.realpath(evidence_dir)
    resolved = os.path.realpath(candidate)
    if os.path.commonpath((root, resolved)) != root:
        return None
    return resolved


def audit_row(json_path, row, evidence_dir):
    if row.get("schema", "").startswith(
            "php-fpm-cve-2026-109618-safe-check-"):
        return audit_safe_check(json_path, row, evidence_dir)
    issues = []
    notes = []
    log_path = safe_log_path(evidence_dir, json_path, row)
    log_text = ""
    if not log_path or not os.path.isfile(log_path):
        issues.append("paired GDB log is missing or points outside evidence directory")
    else:
        with open(log_path, "r", errors="replace") as stream:
            log_text = stream.read()
        if "GDB_NOT_STARTED" in log_text:
            notes.append("GDB did not start; this record is a harness/setup failure, not runtime evidence")

    classification = row.get("classification", "unclassified")
    closure = row.get("gdb_closure") or {}
    proof = row.get("proof") or ""
    token = row.get("proof_token")
    if token is None:
        token = "uid=" if row.get("cmd") == "id>/tmp/u" else None

    if classification == "rce_confirmed":
        if row.get("hit") is not True:
            issues.append("rce_confirmed lacks hit=true")
        if not token or token not in proof:
            issues.append("rce_confirmed lacks matching command proof token")
        for key in ("zend_array_destroy_seen", "fake_array_destroy_seen",
                    "system_call_seen"):
            if closure.get(key) is not True:
                issues.append("rce_confirmed lacks %s=true" % key)
        if row.get("attack", {}).get("address_match") is not True:
            issues.append("rce_confirmed lacks attack arData address match")
        if log_text and not re.search(r"(system|vfork|execve)", log_text, re.I):
            issues.append("GDB log has no recognizable process-execution marker")

    elif classification == "patch_control_passed":
        bucket = closure.get("attack_bucket1_at_destroy") or {}
        fake_ht = closure.get("fake_array_ht")
        if row.get("expected_patch_control") is not True:
            issues.append("patch_control_passed lacks expected_patch_control=true")
        if row.get("hit") is not False:
            issues.append("patch_control_passed lacks hit=false")
        if closure.get("zend_array_destroy_seen") is not True:
            issues.append("patch_control_passed lacks outer destroy evidence")
        if closure.get("fake_array_destroy_seen") is not False:
            issues.append("patch_control_passed must show fake array was not destroyed")
        if closure.get("system_call_seen") is not False:
            issues.append("patch_control_passed must show no system call")
        if not bucket.get("ptr") or not fake_ht:
            issues.append("patch_control_passed lacks bucket pointer comparison")
        elif bucket["ptr"].lower() == fake_ht.lower():
            issues.append("patch_control_passed bucket pointer still targets fake array")
        if bucket.get("type_info") in (None, "0x107"):
            issues.append("patch_control_passed lacks patched bucket type_info")

    elif classification == "environment_blocked":
        if "ptrace: Function not implemented" not in log_text:
            issues.append("environment_blocked lacks matching ptrace error in GDB log")
        if row.get("status") != "failed":
            issues.append("environment_blocked lacks status=failed")

    elif row.get("status") == "failed" and not (
            row.get("failure_root_evidence") or row.get("error")):
        issues.append("failed run has no recorded root-cause evidence")

    root_evidence = row.get("failure_root_evidence") or row.get("error") or []
    if isinstance(root_evidence, str):
        root_evidence = [root_evidence]
    root_text = " ".join(str(item) for item in root_evidence).lower()
    if any(marker in root_text for marker in
           ("unproven", "unresolved", "not proven", "remains unknown")):
        issues.append("root-cause record explicitly says the cause remains unresolved")
    if classification == "unclassified":
        notes.append("record predates the classification field")

    return {
        "record": os.path.basename(json_path),
        "php_image": row.get("tag"),
        "container_image_id": row.get("container", {}).get("image_id"),
        "finished_at_utc": row.get("finished_at_utc"),
        "classification": classification,
        "status": row.get("status", "completed"),
        "paired_gdb_log": os.path.basename(log_path) if log_path else None,
        "json_sha256": sha256(json_path),
        "gdb_sha256": sha256(log_path) if log_path and os.path.isfile(log_path) else None,
        "issues": issues,
        "notes": notes,
        "audit_result": "pass" if not issues else "review_required",
    }


def audit_safe_check(json_path, row, evidence_dir):
    """Audit a read-only checker report without treating it as exploit proof."""
    issues = []
    notes = ["read-only PHP-FPM build/config evidence; not exploit evidence"]
    log_path = safe_log_path(evidence_dir, json_path, row)
    log_text = ""
    if not log_path or not os.path.isfile(log_path):
        issues.append("paired GDB-N/A log is missing or points outside evidence directory")
    else:
        with open(log_path, "r", errors="replace") as stream:
            log_text = stream.read()
        if "GDB_NOT_APPLICABLE" not in log_text:
            issues.append("read-only checker sidecar lacks GDB_NOT_APPLICABLE")

    commands = row.get("commands", {}).get("commands", [])
    failure = row.get("failure_analysis") or {}
    result = row.get("result") or {}
    source = row.get("source") or {}
    complete = failure.get("complete") is True
    if complete:
        if len(commands) != 4:
            issues.append("completed safe check does not contain the four expected command records")
        for command in commands:
            if command.get("exit_code") != 0 or command.get("timed_out"):
                issues.append("completed safe check contains a failed or timed-out command")
            if source.get("kind") == "local_image" and command.get("cleanup_verified_absent") is not True:
                issues.append("image-mode command lacks verified temporary-container cleanup")
        for field in ("php_version", "container_architecture"):
            if not result.get(field):
                issues.append("completed safe check lacks result.%s" % field)
        if result.get("sapi_fpm_fastcgi_confirmed") is not True:
            issues.append("completed safe check lacks FPM/FastCGI confirmation")
        if result.get("platform_match") is False:
            issues.append("completed safe check claims completion despite a platform mismatch")
    else:
        failures = failure.get("failures") or []
        if not failures:
            issues.append("incomplete safe check lacks failure-analysis records")
        for item in failures:
            if not item.get("root_cause") or not item.get("analysis"):
                issues.append("safe-check failure lacks root cause and analysis")
            if source.get("kind") == "local_image" and item.get("cleanup_verified_absent") is not True:
                issues.append("failed image-mode command lacks verified temporary-container cleanup")
        notes.append("collection did not complete; this is an explained environment/setup result")

    serialized_commands = json.dumps(row.get("commands", {}), sort_keys=True)
    if '"stdout"' in serialized_commands or '"stderr"' in serialized_commands:
        issues.append("safe-check JSON persisted raw command output instead of hashes/sizes")
    phpinfo_hash = result.get("phpinfo_sha256")
    if phpinfo_hash and not re.fullmatch(r"[0-9a-f]{64}", phpinfo_hash):
        issues.append("phpinfo_sha256 is not a SHA-256 hex digest")

    classification = "safe_check_completed" if complete else "safe_check_environment_failure"
    return {
        "record": os.path.basename(json_path),
        "php_image": source.get("image") or source.get("container"),
        "container_image_id": row.get("commands", {}).get("image_id_arch"),
        "finished_at_utc": row.get("generated_at_utc"),
        "classification": classification,
        "status": "completed" if complete else "failed",
        "paired_gdb_log": os.path.basename(log_path) if log_path else None,
        "json_sha256": sha256(json_path),
        "gdb_sha256": sha256(log_path) if log_path and os.path.isfile(log_path) else None,
        "issues": issues,
        "notes": notes,
        "audit_result": "pass" if not issues else "review_required",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", required=True,
                        help="directory containing per-run JSON and GDB logs")
    parser.add_argument("--output", required=True,
                        help="write the audit JSON report to this path")
    args = parser.parse_args()

    evidence_dir = os.path.realpath(args.evidence_dir)
    if not os.path.isdir(evidence_dir):
        parser.error("evidence directory does not exist: " + evidence_dir)

    findings = []
    malformed = []
    documents_without_runs = 0
    for json_path in sorted(glob.glob(os.path.join(evidence_dir, "*.json"))):
        try:
            with open(json_path, "r", errors="replace") as stream:
                document = json.load(stream)
        except Exception as exc:  # noqa: BLE001
            malformed.append({"record": os.path.basename(json_path),
                              "error": "%s: %s" % (type(exc).__name__, exc)})
            continue
        rows = rows_from_document(document)
        if not rows:
            documents_without_runs += 1
        for row in rows:
            findings.append(audit_row(json_path, row, evidence_dir))

    counts = {}
    for finding in findings:
        key = finding["classification"]
        counts[key] = counts.get(key, 0) + 1
    for finding in findings:
        image_id = finding.get("container_image_id")
        finished = finding.get("finished_at_utc")
        if not image_id or not finished or not finding["issues"]:
            continue
        later = [
            {"record": other["record"],
             "classification": other["classification"],
             "finished_at_utc": other.get("finished_at_utc")}
            for other in findings
            if other is not finding
            and other.get("container_image_id") == image_id
            and other.get("finished_at_utc")
            and other["finished_at_utc"] > finished
            and other.get("classification") in
                ("rce_confirmed", "patch_control_passed")
            and other.get("audit_result") == "pass"
        ]
        if later:
            finding["related_later_same_build_verified_runs"] = later
            finding["notes"].append(
                "later run(s) with the same image digest passed; this does not resolve the original root cause")
    image_sets = {}
    for finding in findings:
        image = finding.get("php_image")
        if image:
            image_sets.setdefault(finding["classification"], set()).add(image)
    verified_rce_images = sorted(
        finding["php_image"] for finding in findings
        if finding.get("classification") == "rce_confirmed"
        and finding.get("audit_result") == "pass" and finding.get("php_image"))
    verified_patch_images = sorted(
        finding["php_image"] for finding in findings
        if finding.get("classification") == "patch_control_passed"
        and finding.get("audit_result") == "pass" and finding.get("php_image"))
    report = {
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "mode": "read_only_evidence_audit",
        "evidence_dir": evidence_dir,
        "summary": {
            "run_records": len(findings),
            "classification_counts": counts,
            "audit_pass": sum(1 for item in findings
                              if item["audit_result"] == "pass"),
            "review_required": sum(1 for item in findings
                                   if item["audit_result"] != "pass"),
            "malformed_json_files": len(malformed),
            "non_run_json_documents": documents_without_runs,
            "verified_local_rce_image_tags": sorted(set(verified_rce_images)),
            "verified_patch_control_image_tags": sorted(set(verified_patch_images)),
            "image_tags_by_classification": {
                key: sorted(values) for key, values in sorted(image_sets.items())
            },
        },
        "records": findings,
        "malformed_json": malformed,
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps(report["summary"], sort_keys=True))
    print("report: %s" % os.path.abspath(args.output))
    return 1 if malformed or report["summary"]["review_required"] else 0


if __name__ == "__main__":
    sys.exit(main())
