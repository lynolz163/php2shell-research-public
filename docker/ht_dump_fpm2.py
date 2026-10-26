# ht_dump_fpm2.py -- ground-truth probe for the FPM script-stage path.
#
# Fix over ht_dump_fpm.py: the huge outer-name insert 'Z*n[x]' goes through
# zend_symtable_str_update_ind (inline in zend_hash.h) which calls the
# exported ZEND_API symbol **zend_hash_str_update_ind** -- NOT
# zend_hash_str_update.
#
# At the breakpoint (entry, before the body runs) $out already holds its
# arData from the 'a=1' insert, and nNumUsed has NOT been bumped yet, so:
#   bucket0 = the real 'a' entry
#   bucket1 = the STALE bucket = raw pattern bytes (if the dance worked)
# which settles, in the EXACT exploit GET shape:
#   - the true arData chunk offset (ARDATA_OFF)
#   - the true pattern<->arData adjacency (P0) via bucket1 content
# Lab probe only.

import re

SYSTEM_RETURN_BREAKPOINTS = []
import struct
import os

import gdb

BUCKET = 32

_ACTIVE_WPS = []
_HUGEKEYS_SEEN = 0
_SKIP_HUGEKEYS = int(os.environ.get("FPM_GDB_SKIP_HUGEKEYS", "0"))


def arg_register(index):
    """Return the System V/AAPCS argument register for this target."""
    arch = gdb.selected_frame().architecture().name().lower()
    if "aarch64" in arch or "arm64" in arch:
        return ("x0", "x1", "x2")[index]
    if "x86-64" in arch or "x86_64" in arch:
        return ("rdi", "rsi", "rdx")[index]
    raise RuntimeError("unsupported target architecture: %s" % arch)


def trace_fatal_signal(event):
    """Keep the first fatal signal's backtrace in the retained gdb log."""
    name = getattr(event, "stop_signal", "")
    if name in ("SIGABRT", "SIGSEGV"):
        print("SIGNAL_TRACE %s" % name)
        try:
            gdb.execute("bt 20")
            frame = gdb.newest_frame()
            depth = 0
            while frame is not None and depth < 12:
                pc = int(frame.pc())
                print("SIGNAL_FRAME depth=%d name=%s pc=0x%x" %
                      (depth, frame.name(), pc))
                try:
                    gdb.execute("info symbol 0x%x" % pc)
                    if depth >= 3:
                        gdb.execute("x/12i 0x%x" % max(0, pc - 16))
                except Exception as symbol_exc:  # noqa: BLE001
                    print("SIGNAL_FRAME_SYMBOL_ERROR depth=%d error=%r" %
                          (depth, symbol_exc))
                frame = frame.older()
                depth += 1
            gdb.execute("info registers")
            gdb.execute("x/24gx $sp")
        except Exception as exc:  # noqa: BLE001
            print("SIGNAL_TRACE_BACKTRACE_ERROR %r" % exc)


def rd(addr, n):
    return bytes(gdb.selected_inferior().read_memory(int(addr), n))


def u32(addr):
    return struct.unpack("<I", rd(addr, 4))[0]


def u64(addr):
    return struct.unpack("<Q", rd(addr, 8))[0]


def try_rd(addr, n):
    try:
        return rd(addr, n)
    except gdb.MemoryError:
        return None


def dump_rows(addr, total):
    for row in range(0, total, 16):
        a = addr + row
        raw = try_rd(a, 16)
        if raw is None:
            print("  0x%x  <unmapped>" % a)
            continue
        print("  0x%x  %s  |%s|"
              % (a, raw.hex(" ", 8),
                 "".join(chr(b) if 32 <= b < 127 else "." for b in raw)))


class HugeKeyInd(gdb.Breakpoint):
    def __init__(self):
        gdb.execute("set breakpoint pending on", to_string=True)
        # '*symbol' = exact entry address; at entry x0=ht, x1=key, x2=len
        # (AAPCS).  The default symbol location lands after the prologue
        # where x0 has already been reloaded with the key for the hash.
        super(HugeKeyInd, self).__init__("*zend_hash_str_update_ind",
                                         internal=False)

    def stop(self):
        global _HUGEKEYS_SEEN
        _HUGEKEYS_SEEN += 1
        fr = gdb.selected_frame()
        ht = int(fr.read_register(arg_register(0)))
        ln = int(fr.read_register(arg_register(2)))
        if ln < (1 << 20):
            return False
        try:
            ar = u64(ht + 0x10)
            gc_refcount = u32(ht)
            gc_type_info = u32(ht + 4)
            nu = u32(ht + 0x18)
            nts = u32(ht + 0x20)
            bkt = try_rd(ar, 3 * BUCKET)
        except gdb.MemoryError:
            print("HUGEKEYIND ht=0x%x len=%d <ht read error>" % (ht, ln))
            return False
        print("HUGEKEYIND arch=%s ht=0x%x len=%d gc_refcount=%d gc_type_info=0x%x "
              "arData=0x%x nNumUsed=%d "
              "nTableSize=%d off=0x%x\n     buckets=%s"
              % (gdb.selected_frame().architecture().name(),
                 ht, ln, gc_refcount, gc_type_info, ar, nu, nts, ar & 0x1FFFFF,
                 bkt.hex() if bkt else "?"))
        print("--- buckets (arData .. +0x60) ---")
        dump_rows(ar, 0x60)
        print("--- pattern window (arData-0x80 .. arData) ---")
        dump_rows(ar - 0x80, 0x80)
        print("--- fake-array calibration window (arData+0x80 .. +0xC0) ---")
        dump_rows(ar + 0x80, 0x40)
        # runtime destroy tracing: hardware watchpoints (Python class so a
        # hit logs and CONTINUES instead of ending the batch session).
        # HW watchpoints are scarce (4 on arm64): clear the previous set.
        global _ACTIVE_WPS
        # watch ONLY the attack dance (n=4700001; the calibration dances
        # use n=4700000).  Arm ONCE: re-arming across dances exhausts the
        # 4 hardware watchpoint slots on this gdb (no gdb.Watchpoint class
        # to delete cleanly).
        if (_HUGEKEYS_SEEN <= _SKIP_HUGEKEYS or ln == 4700000
                or ln >= (1 << 24) or _ACTIVE_WPS):
            return False
        try:
            _ACTIVE_WPS.append(ArmRead(ar, "bucket0.val"))
            _ACTIVE_WPS.append(ArmRead(ar + 0x20, "bucket1.val"))
            fake = u64(ar + 0x20)
            if 0x10000 < fake < 0x10000_0000_0000:
                _ACTIVE_WPS.append(ArmAccess(fake, "fake.gc"))
            _ACTIVE_WPS.append(ArmAccess(ht, "out.gc.refcount"))
            print("WATCHES armed (bucket0/bucket1, fake.gc, out.gc.refcount)")
        except Exception as exc:  # noqa: BLE001
            print("watchpoint arming failed: %r" % exc)
        return False


class ArrDestroyV(gdb.Breakpoint):
    def __init__(self):
        gdb.execute("set breakpoint pending on", to_string=True)
        super(ArrDestroyV, self).__init__("zend_array_destroy",
                                          internal=False)

    def stop(self):
        fr = gdb.selected_frame()
        ht = int(fr.read_register(arg_register(0)))
        try:
            ar = u64(ht + 0x10)
            nu = u32(ht + 0x18)
            nts = u32(ht + 0x20)
        except gdb.MemoryError:
            return False
        if ar == 0 or nu == 0 or nts == 0 or nts > 4096:
            return False
        blob = try_rd(ar, min(max(nu, 1) + 1, 4) * BUCKET)
        if blob is None:
            return False
        print("DEST ht=0x%x arData=0x%x nNumUsed=%d nTableSize=%d\n"
              "     buckets=%s" % (ht, ar, nu, nts, blob.hex()))
        return False


class SystemPath(gdb.Breakpoint):
    """Observe the implementation body reached from the system wrapper."""
    def __init__(self, address):
        super(SystemPath, self).__init__("*0x%x" % address, internal=False)

    def stop(self):
        fr = gdb.selected_frame()
        print("SYSTEM_PATH_BODY pc=0x%x" % int(fr.pc()))
        try:
            gdb.execute("info registers")
            gdb.execute("x/20i $pc")
            gdb.execute("bt 12")
        except Exception as exc:  # noqa: BLE001
            print("SYSTEM_PATH_BODY_ERROR %r" % exc)
        return False


class SystemCall(gdb.Breakpoint):
    """Record whether the forged destructor actually reaches system()."""
    def __init__(self):
        gdb.execute("set breakpoint pending on", to_string=True)
        super(SystemCall, self).__init__("*system", internal=False)

    def stop(self):
        fr = gdb.selected_frame()
        arg0 = int(fr.read_register(arg_register(0)))
        raw = try_rd(arg0, 32)
        if raw is None:
            print("SYSTEM_CALL arg0=0x%x bytes=<unmapped>" % arg0)
        else:
            shown = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
            print("SYSTEM_CALL arg0=0x%x bytes=%s text=%r"
                  % (arg0, raw.hex(), shown))
        arch = fr.architecture().name().lower()
        stack_reg, frame_reg, link_reg = (("sp", "x29", "x30")
                                           if "aarch64" in arch or "arm64" in arch
                                           else ("rsp", "rbp", "rip"))
        try:
            print("SYSTEM_CALL_REGS sp=0x%x fp=0x%x lr=0x%x"
                  % (int(fr.read_register(stack_reg)),
                     int(fr.read_register(frame_reg)),
                     int(fr.read_register(link_reg))))
            print("SYSTEM_CALL_PC pc=0x%x" % int(fr.pc()))
            gdb.execute("x/16i $pc")
            gdb.execute("x/16gx $sp")
            try:
                gdb.execute("disassemble __libc_system")
                gdb.execute("disassemble do_system")
                body_addr = int(gdb.parse_and_eval("&do_system")) + 32
                print("SYSTEM_DO_SYSTEM_BODY_ADDR addr=0x%x" % body_addr)
                body_bp = SystemPath(body_addr)
                SYSTEM_RETURN_BREAKPOINTS.append(body_bp)
            except Exception as disasm_exc:  # noqa: BLE001
                print("SYSTEM_DO_SYSTEM_DISASM_ERROR %r" % disasm_exc)
            gdb.execute("bt 12")
            if "aarch64" in arch or "arm64" in arch:
                return_addr = int(fr.read_register("x30"))
            else:
                return_addr = u64(int(fr.read_register("rsp")))
            if return_addr:
                print("SYSTEM_CALL_RETURN_SITE addr=0x%x" % return_addr)
                return_bp = SystemReturn(return_addr)
                SYSTEM_RETURN_BREAKPOINTS.append(return_bp)
                print("SYSTEM_RETURN_BP number=%s enabled=%s location=%s"
                      % (return_bp.number, return_bp.enabled,
                         return_bp.location))
        except Exception as exc:  # noqa: BLE001
            print("SYSTEM_CALL_BT_ERROR %r" % exc)
        return False


class SystemReturn(gdb.Breakpoint):
    """Record the return value if libc system() returns to Zend."""
    def __init__(self, address):
        self.address = address
        super(SystemReturn, self).__init__("*0x%x" % address,
                                          temporary=True, internal=True)

    def stop(self):
        fr = gdb.selected_frame()
        arch = fr.architecture().name().lower()
        ret_reg = "x0" if "aarch64" in arch or "arm64" in arch else "rax"
        try:
            value = int(fr.read_register(ret_reg))
            print("SYSTEM_RETURN pc=0x%x value=0x%x signed=%d"
                  % (int(fr.pc()), value, value if value < (1 << 63)
                     else value - (1 << 64)))
            gdb.execute("bt 8")
        except Exception as exc:  # noqa: BLE001
            print("SYSTEM_RETURN_ERROR %r" % exc)
        return False


class FunctionTrace(gdb.Breakpoint):
    """Log selected libc execution/failure boundaries without stopping."""
    def __init__(self, symbol):
        self.symbol = symbol
        gdb.execute("set breakpoint pending on", to_string=True)
        super(FunctionTrace, self).__init__("*" + symbol, internal=False)

    def stop(self):
        fr = gdb.selected_frame()
        try:
            arg0 = int(fr.read_register(arg_register(0)))
            raw = try_rd(arg0, 32)
            arg_text = (raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
                        if raw is not None else "<unmapped>")
        except Exception as exc:  # noqa: BLE001
            arg0, arg_text = 0, "<error %s>" % exc
        print("FUNCTION_HIT symbol=%s pc=0x%x arg0=0x%x arg0_text=%r"
              % (self.symbol, int(fr.pc()), arg0, arg_text))
        try:
            gdb.execute("bt 8")
        except Exception as exc:  # noqa: BLE001
            print("FUNCTION_BT_ERROR symbol=%s error=%r" % (self.symbol, exc))
        return False


class ArmRead(gdb.Breakpoint):
    """Hardware READ watchpoint that logs and continues.

    Falls back from gdb.Watchpoint (gdb >= 12) to a silent Breakpoint-based
    harness is not possible, so older gdbs use raw rwatch commands with
    an auto-continue command list.
    """

    HAVE_PY_WP = hasattr(gdb, "Watchpoint")

    def __init__(self, addr, tag):
        self.tag = tag
        self.addr = addr
        if ArmRead.HAVE_PY_WP:
            try:
                super(ArmRead, self).__init__("*(unsigned long*)%d" % addr,
                                              gdb.WP_READ, internal=False)
                return
            except TypeError:
                super(ArmRead, self).__init__("*(unsigned long*)%d" % addr,
                                              type=gdb.WP_READ,
                                              internal=False)
                return
        created = gdb.execute("rwatch *(unsigned long*)%d" % addr,
                              to_string=True)
        self.raw = True
        nums = re.findall(r"watchpoint (\d+)", created, re.I)
        self.num = int(nums[-1]) if nums else None
        if self.num is not None:
            print("WATCHPOINT_AUTOCONTINUE num=%d tag=%s" % (self.num, tag))
            extra_bt = "bt 8\n" if tag == "out.gc.refcount" else ""
            gdb.execute("commands %d\nsilent\nprintf \"WATCHPOINT_HIT %s val=0x%%lx\\n\", *(unsigned long*)%d\n%scontinue\nend"
                        % (self.num, tag, self.addr, extra_bt))
        else:
            print("WATCHPOINT_AUTOCONTINUE_FAILED tag=%s created=%r"
                  % (tag, created))

    def stop(self):
        try:
            v = u64(self.addr)
        except gdb.MemoryError:
            v = -1
        print("RWP %s @0x%x val=0x%x" % (self.tag, self.addr, v))
        return False


class ArmAccess(ArmRead):
    def __init__(self, addr, tag):
        self.tag = tag
        self.addr = addr
        write_only = tag == "out.gc.refcount"
        if ArmRead.HAVE_PY_WP:
            wp_type = gdb.WP_WRITE if write_only else gdb.WP_ACCESS
            try:
                super(ArmAccess, self).__init__("*(unsigned long*)%d" % addr,
                                                wp_type,
                                                internal=False)
                return
            except TypeError:
                super(ArmAccess, self).__init__("*(unsigned long*)%d" % addr,
                                                type=wp_type,
                                                internal=False)
                return
        command = "watch" if write_only else "awatch"
        created = gdb.execute("%s *(unsigned long*)%d" % (command, addr),
                              to_string=True)
        self.raw = True
        nums = re.findall(r"watchpoint (\d+)", created, re.I)
        self.num = int(nums[-1]) if nums else None
        if self.num is not None:
            print("WATCHPOINT_AUTOCONTINUE num=%d tag=%s" % (self.num, tag))
            extra_bt = "bt 8\n" if tag == "out.gc.refcount" else ""
            gdb.execute("commands %d\nsilent\nprintf \"WATCHPOINT_HIT %s val=0x%%lx\\n\", *(unsigned long*)%d\n%scontinue\nend"
                        % (self.num, tag, self.addr, extra_bt))
        else:
            print("WATCHPOINT_AUTOCONTINUE_FAILED tag=%s created=%r"
                  % (tag, created))


HugeKeyInd()
ArrDestroyV()
SystemCall()
for _trace_symbol in (
        "do_system", "__posix_spawn", "posix_spawn", "__spawn",
        "vfork", "__vfork", "__libc_vfork", "fork", "__fork",
        "__libc_fork", "posix_spawn", "__posix_spawn", "clone",
        "__clone", "__clone_internal", "clone3", "execve", "__execve",
        "__stack_chk_fail", "__stack_chk_fail_local", "__fortify_fail",
        "__GI___realpath"):
    try:
        FunctionTrace(_trace_symbol)
    except gdb.error as _trace_error:
        print("FUNCTION_TRACE_UNAVAILABLE symbol=%s error=%s"
              % (_trace_symbol, _trace_error))
gdb.events.stop.connect(trace_fatal_signal)
print("ht_dump_fpm2.py armed arch=%s skip=%d"
      % (gdb.selected_frame().architecture().name(), _SKIP_HUGEKEYS))
print("ht_dump_fpm2.py watchpoint_api=%s" % ArmRead.HAVE_PY_WP)
