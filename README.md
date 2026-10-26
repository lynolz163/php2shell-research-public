# PHP-FPM CVE-2026-109618 research lab

This repository is a self-contained Docker lab for reproducing the request-parsing bug tracked as **CVE-2026-109618** and **GHSA-w8hw-w9fx-j79w**. It contains the PHP-FPM fixtures, calibration scripts, debugger probe, and a small set of validation commands. It does not contain experiment results, JSON evidence, gdb transcripts, image digests, or local machine paths.

Run it only on a machine you control. The default proof command writes a short file inside the test container; it does not contact an external host.

## What the bug does

The vulnerable path is a use-after-free of a partially initialized hash-table bucket during request shutdown:

1. PHP parses a URL-encoded field and increments the destination hash table's `nNumUsed` counter before allocating the field name.
2. A deliberately oversized field name makes the name allocation hit `memory_limit`. PHP bails out while the new bucket still contains stale bytes from a previous allocation.
3. The script-stage fixture keeps the destination array alive until shutdown. Destruction walks the bucket that was counted but never initialized.
4. The first allocation in the request is arranged so that the stale bucket contains bytes controlled by the request. Those bytes describe a zval and a small fake hash table.
5. The fake table's destructor pointer is used as a callback. In the lab proof it points to `system()`, which runs a short operator-selected command as the FPM worker user.

The important distinction for PHP-FPM is the request phase. An OOM during startup POST parsing normally kills the worker before the useful shutdown path. The fixture instead calls `parse_str()` from a script, so the bailout happens after the script has started and the shutdown callback can destroy the array.

The exploit is sensitive to the PHP build, allocator, architecture, and worker layout. The runner therefore measures the live `arData` and `system` addresses for each temporary container instead of shipping hard-coded addresses.

## Requirements

- Docker Desktop, Colima, or another Docker Engine
- Python 3.9+
- `curl`
- A Docker host that can run the selected image architecture. Use a native amd64 host or a configured multi-architecture runtime for the `x86_64-*` samples.

The FPM matrix installs gdb inside its temporary container. No debugger or PHP package is installed on the host.

## Start the base lab

```bash
git clone https://github.com/lynolz163/php2shell-research-public.git
cd php2shell-research-public

scripts/start.sh
curl --fail --silent http://127.0.0.1:28085/index.php
```

The launcher starts four Apache/mod_php controls and two PHP-FPM plus nginx controls. Every published port is bound to `127.0.0.1`. `scripts/check_env.sh` records a local environment snapshot under the ignored `evidence/` directory when you need one.

## Reproduce a PHP-FPM sample

The main driver creates a short-lived network and container for each branch, performs a non-triggering calibration request, attaches the supplied gdb probe, and then runs the proof request. The default proof command is `id>/tmp/u`.

```bash
python3 tests/fpm_eol_matrix.py --help

python3 tests/fpm_eol_matrix.py \
  --branches 8.4 \
  --rounds 1 \
  --cmd 'id>/tmp/u' \
  --out-dir out/fpm-8.4
```

The branch aliases currently available in the driver are:

| Alias | Image | Purpose |
|---|---|---|
| `7.4`, `8.0`, `8.1` | `php:7.4.33-fpm`, `php:8.0.30-fpm`, `php:8.1.33-fpm` | EOL samples |
| `8.2`, `8.3`, `8.4`, `8.5` | `php:8.2.34-fpm`, `php:8.3.35-fpm`, `php:8.4.26-fpm`, `php:8.5.11-fpm` | affected release-point samples |
| `8.2.35`, `8.3.36`, `8.4.27`, `8.5.12` | matching fixed-release images | patch controls |
| `x86_64-8.1`, `x86_64-8.0`, `x86_64-7.4`, `x86_64-8.5` | matching tags with `linux/amd64` | x86_64 samples |
| `alpine-8.1`, `alpine-8.4` | matching `-fpm-alpine` images | musl samples |

Run several samples in one bounded invocation:

```bash
python3 tests/fpm_eol_matrix.py \
  --branches 8.1,8.0,7.4,8.5,x86_64-8.1,x86_64-8.0,x86_64-7.4,x86_64-8.5 \
  --rounds 1 \
  --cmd 'id>/tmp/u' \
  --out-dir out/fpm-matrix
```

## Choose a harmless proof command

The proof command is an explicit operator input. It is limited to 23 UTF-8 bytes because the command string is placed in the controlled bucket layout. Use a command that only creates a file inside the container:

```bash
python3 tests/fpm_eol_matrix.py \
  --branches 8.4 \
  --cmd 'printf 1>/tmp/poc-proof' \
  --proof-path /tmp/poc-proof \
  --proof-token 1 \
  --out-dir out/fpm-manual
```

`touch /tmp/poc-proof` is another short example. Do not use a command that reaches the host, a production service, or the public network. `--kind oracle` runs the destructor-path check with an unmapped callback target and does not attempt command execution.

## Read the local result

The driver writes one JSON record and one `.gdb.log` beside it under the directory passed to `--out-dir`. These files are intentionally ignored by Git. A run is considered a command-execution proof only when the record contains the configured proof output and the gdb trace shows the outer destroy, fake-table destroy, and process-execution path. A crash or an address match alone is not a success.

For a read-only consistency check after a run:

```bash
python3 tests/fpm_evidence_audit.py \
  --evidence-dir out/fpm-matrix \
  --output /tmp/fpm-evidence-audit.json
```

The audit utility never starts a container, sends an HTTP request, or executes a payload.

## Other useful checks

```bash
python3 tests/fpm_patch_marker_check.py --help  # inspect an existing FPM image/container
python3 tests/sapi_matrix.py --help             # CLI/ZTS boundary samples
python3 tests/test_cve_109618_oom.py --help     # basic mod_php OOM trigger
python3 tests/fpm_oracle.py                     # destructor-path oracle in the base FPM lab
```

The optional gdb image can be built for the Apache-side probe:

```bash
docker build --build-arg PHP_VERSION=8.4.26 \
  -f docker/Dockerfile.gdb -t php-gdb:8.4.26 .
```

## Repository layout

| Path | Purpose |
|---|---|
| `config/` | Apache, nginx, PHP and FPM lab configuration |
| `docker/` | gdb bootstrap, debugger probes and the optional Apache gdb image |
| `scripts/` | bounded start, environment check, stop and cleanup helpers |
| `tests/` | FPM matrix, calibration, oracle, SAPI and OOM validation drivers |
| `webroot/` | the request fixtures used by the drivers |
| `docker-compose.yml` | equivalent local service definition |

Generated `evidence/`, `out/`, JSON, log, and gdb transcript files are local run products and are excluded from the public repository.

## Stop the lab

```bash
scripts/stop.sh   # stop this lab's containers
scripts/clean.sh  # remove this lab's containers and php2shell-net
```

Both helpers are project-scoped. They do not run a global Docker prune and do not touch other projects.

## Scope

This is a research fixture, not a scanner and not a production deployment. The version aliases are concrete Docker image tags used by the driver; vendor backports, compiler changes, allocator differences, and pool settings can change the result. Keep any public report tied to the exact image, architecture, configuration, and local run output used to produce it.
