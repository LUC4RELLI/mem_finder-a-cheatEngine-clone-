"""
Hardware watchpoints via Linux ptrace debug registers (x86_64).

Uses DR0-DR3 for watchpoint addresses and DR7 for configuration.
When a watchpoint fires (SIGTRAP), reads RIP to identify caller.
Optionally disassembles with capstone.
"""
from __future__ import annotations
import ctypes
import ctypes.util
import os
import signal
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

# ── ptrace constants ──────────────────────────────────────────────────────────
PTRACE_ATTACH      = 16
PTRACE_DETACH      = 17
PTRACE_CONT        = 7
PTRACE_PEEKUSER    = 3
PTRACE_POKEUSER    = 6
PTRACE_GETREGS     = 12
PTRACE_GETSIGINFO  = 0x4202

# x86_64 user struct offsets for debug registers (bytes)
# Defined in <sys/user.h> — struct user, u_debugreg array starts at offset 848
_DR_BASE_OFFSET = 848
DR_OFFSETS = {
    0: _DR_BASE_OFFSET + 0 * 8,   # DR0 = 848
    1: _DR_BASE_OFFSET + 1 * 8,   # DR1 = 856
    2: _DR_BASE_OFFSET + 2 * 8,   # DR2 = 864
    3: _DR_BASE_OFFSET + 3 * 8,   # DR3 = 872
    6: _DR_BASE_OFFSET + 6 * 8,   # DR6 = 896  (status)
    7: _DR_BASE_OFFSET + 7 * 8,   # DR7 = 912  (control)
}

# DR7 condition codes (bits [17:16], [21:20], [25:24], [29:28] per watchpoint)
_COND_EXECUTE = 0b00
_COND_WRITE   = 0b01
_COND_READWRITE = 0b11

# DR7 size codes (bits [19:18], [23:22], [27:26], [31:30])
_SIZE_1 = 0b00
_SIZE_2 = 0b01
_SIZE_4 = 0b11
_SIZE_8 = 0b10

_SIZE_MAP = {1: _SIZE_1, 2: _SIZE_2, 4: _SIZE_4, 8: _SIZE_8}

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
_libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long,
                          ctypes.c_void_p, ctypes.c_void_p]
_libc.ptrace.restype = ctypes.c_long


def _ptrace(request: int, pid: int, addr: int = 0, data: int = 0) -> int:
    return _libc.ptrace(
        ctypes.c_long(request), ctypes.c_long(pid),
        ctypes.c_void_p(addr), ctypes.c_void_p(data),
    )


# ── Capstone disassembly (optional) ──────────────────────────────────────────

def _try_disasm(ip: int, code: bytes) -> str:
    try:
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = False
        for insn in md.disasm(code, ip):
            return f"{insn.mnemonic} {insn.op_str}"
    except Exception:
        pass
    return "<disasm unavailable>"


@dataclass
class WatchpointHit:
    watchpoint_addr: int
    caller_ip:       int
    instruction:     str
    thread_id:       int
    timestamp:       float
    access_type:     str   # "read", "write", "exec"

    def format(self) -> str:
        ts = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        ms = int((self.timestamp % 1) * 1000)
        return (
            f"[{ts}.{ms:03d}] WP@0x{self.watchpoint_addr:X} "
            f"accessed by 0x{self.caller_ip:X} ({self.instruction}) "
            f"tid={self.thread_id}"
        )


class WatchpointManager:
    """
    Manages up to 4 hardware watchpoints on a Linux x86_64 process.

    Limitations:
    - Requires ptrace attach (same UID, or root, or ptrace_scope=0).
    - Max 4 simultaneous watchpoints (x86_64 DR0-DR3).
    - The target process must be running (not stopped) before use.
    """

    MAX_SLOTS = 4

    def __init__(self, pid: int,
                 hit_callback: Optional[Callable[[WatchpointHit], None]] = None):
        self.pid = pid
        self.hit_callback = hit_callback
        # slot_index -> (address, watch_type, size)
        self._slots: dict[int, tuple[int, str, int]] = {}
        self._thread: Optional[_WatchThread] = None
        self._attached = False
        self._lock = threading.Lock()

    def _find_free_slot(self) -> Optional[int]:
        for i in range(self.MAX_SLOTS):
            if i not in self._slots:
                return i
        return None

    def _get_all_thread_ids(self) -> list[int]:
        try:
            return [int(t) for t in os.listdir(f"/proc/{self.pid}/task")]
        except Exception:
            return [self.pid]

    def _write_dr(self, tid: int, dr_num: int, value: int) -> bool:
        offset = DR_OFFSETS.get(dr_num)
        if offset is None:
            return False
        ret = _ptrace(PTRACE_POKEUSER, tid, offset, value)
        return ret == 0

    def _read_dr(self, tid: int, dr_num: int) -> int:
        offset = DR_OFFSETS.get(dr_num)
        if offset is None:
            return 0
        ret = _ptrace(PTRACE_PEEKUSER, tid, offset, 0)
        if ret == -1:
            return 0
        # ptrace returns the value directly (signed long), convert to unsigned
        return ret & 0xFFFFFFFFFFFFFFFF

    def _build_dr7(self) -> int:
        """Rebuild the DR7 control register from current slot configuration."""
        dr7 = 0
        for slot, (addr, wtype, size) in self._slots.items():
            # Enable local breakpoint for slot (bits 0,2,4,6 for slots 0-3)
            dr7 |= (1 << (slot * 2))
            # Condition code
            if wtype == "exec":
                cond = _COND_EXECUTE
            elif wtype == "write":
                cond = _COND_WRITE
            else:  # "rw"
                cond = _COND_READWRITE
            size_code = _SIZE_MAP.get(size, _SIZE_4)
            # Bits [17:16],[21:20],... for cond; [19:18],[23:22],... for size
            shift = 16 + slot * 4
            dr7 |= (cond << shift) | (size_code << (shift + 2))
        return dr7

    def _apply_watchpoints_to_tid(self, tid: int) -> None:
        """Apply all current watchpoints to a single thread."""
        dr7 = self._build_dr7()
        for slot, (addr, _, _) in self._slots.items():
            self._write_dr(tid, slot, addr)
        # Clear DR6 status
        self._write_dr(tid, 6, 0)
        self._write_dr(tid, 7, dr7)

    def _apply_all(self) -> None:
        for tid in self._get_all_thread_ids():
            # Each thread needs separate ptrace attach on Linux
            try:
                _ptrace(PTRACE_ATTACH, tid)
                os.waitpid(tid, 0)
                self._apply_watchpoints_to_tid(tid)
                _ptrace(PTRACE_CONT, tid, 0, 0)
            except Exception:
                pass

    def start(self) -> None:
        """Start the watchpoint monitor thread."""
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._thread = _WatchThread(
                pid=self.pid,
                manager=self,
                hit_callback=self.hit_callback,
            )
            self._thread.daemon = True
            self._thread.start()

    def stop(self) -> None:
        """Stop the watchpoint monitor and detach."""
        with self._lock:
            if self._thread:
                self._thread.stop()
                self._thread.join(timeout=3.0)
                self._thread = None

    def add_watchpoint(self, addr: int,
                       watch_type: str = "rw",
                       size: int = 4) -> bool:
        """
        Add a hardware watchpoint.
        watch_type: "exec", "write", "rw" (read+write)
        size: 1, 2, 4, or 8 bytes
        Returns False if no slots available.
        """
        with self._lock:
            slot = self._find_free_slot()
            if slot is None:
                return False
            size = min([1, 2, 4, 8], key=lambda s: abs(s - size))
            self._slots[slot] = (addr, watch_type, size)
            if self._thread and self._thread.is_alive():
                self._thread.request_apply()
            return True

    def remove_watchpoint(self, addr: int) -> bool:
        with self._lock:
            slot = next((s for s, (a, _, _) in self._slots.items()
                         if a == addr), None)
            if slot is None:
                return False
            del self._slots[slot]
            if self._thread and self._thread.is_alive():
                self._thread.request_apply()
            return True

    def list_watchpoints(self) -> list[tuple[int, str, int, int]]:
        """Return list of (slot, addr, type, size)."""
        with self._lock:
            return [(s, a, t, z) for s, (a, t, z) in self._slots.items()]

    @property
    def slot_count(self) -> int:
        return len(self._slots)


class _WatchThread(threading.Thread):
    """
    Background thread that:
    1. Attaches to the target process via ptrace
    2. Sets debug registers to arm watchpoints
    3. Waits for SIGTRAP events and reports hits
    """

    def __init__(self, pid: int, manager: WatchpointManager,
                 hit_callback: Optional[Callable[[WatchpointHit], None]]):
        super().__init__(name=f"watchpoint-{pid}", daemon=True)
        self.pid = pid
        self.manager = manager
        self.hit_callback = hit_callback
        self._stop_event = threading.Event()
        self._apply_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def request_apply(self) -> None:
        self._apply_event.set()

    def _get_user_regs(self, pid: int) -> Optional[dict]:
        """Read general-purpose registers using PTRACE_GETREGS."""
        class UserRegsStruct(ctypes.Structure):
            _fields_ = [
                ("r15", ctypes.c_ulonglong),
                ("r14", ctypes.c_ulonglong),
                ("r13", ctypes.c_ulonglong),
                ("r12", ctypes.c_ulonglong),
                ("rbp", ctypes.c_ulonglong),
                ("rbx", ctypes.c_ulonglong),
                ("r11", ctypes.c_ulonglong),
                ("r10", ctypes.c_ulonglong),
                ("r9",  ctypes.c_ulonglong),
                ("r8",  ctypes.c_ulonglong),
                ("rax", ctypes.c_ulonglong),
                ("rcx", ctypes.c_ulonglong),
                ("rdx", ctypes.c_ulonglong),
                ("rsi", ctypes.c_ulonglong),
                ("rdi", ctypes.c_ulonglong),
                ("orig_rax", ctypes.c_ulonglong),
                ("rip", ctypes.c_ulonglong),
                ("cs",  ctypes.c_ulonglong),
                ("eflags", ctypes.c_ulonglong),
                ("rsp", ctypes.c_ulonglong),
                ("ss",  ctypes.c_ulonglong),
                ("fs_base", ctypes.c_ulonglong),
                ("gs_base", ctypes.c_ulonglong),
                ("ds",  ctypes.c_ulonglong),
                ("es",  ctypes.c_ulonglong),
                ("fs",  ctypes.c_ulonglong),
                ("gs",  ctypes.c_ulonglong),
            ]
        regs = UserRegsStruct()
        ret = _ptrace(PTRACE_GETREGS, pid, 0,
                      ctypes.addressof(regs))
        if ret != 0:
            return None
        return {"rip": regs.rip, "rsp": regs.rsp}

    def run(self) -> None:
        from .memory_io import read_memory as _read_mem

        pid = self.pid
        # Attach to process
        ret = _ptrace(PTRACE_ATTACH, pid)
        if ret != 0:
            return
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass

        # Arm watchpoints
        self.manager._apply_watchpoints_to_tid(pid)
        _ptrace(PTRACE_CONT, pid, 0, 0)

        while not self._stop_event.is_set():
            # Check if we need to re-apply watchpoints
            if self._apply_event.is_set():
                self._apply_event.clear()
                # Stop process to update DRs
                try:
                    os.kill(pid, signal.SIGSTOP)
                    os.waitpid(pid, 0)
                    self.manager._apply_watchpoints_to_tid(pid)
                    _ptrace(PTRACE_CONT, pid, 0, 0)
                except Exception:
                    pass

            # Non-blocking waitpid
            try:
                result = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                break

            child_pid, status = result
            if child_pid == 0:
                time.sleep(0.01)
                continue

            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                break

            if os.WIFSTOPPED(status):
                sig = os.WSTOPSIG(status)
                if sig == signal.SIGTRAP:
                    # Read DR6 to find which watchpoint fired
                    dr6 = self.manager._read_dr(pid, 6)
                    fired_slot = -1
                    for slot in range(4):
                        if dr6 & (1 << slot):
                            fired_slot = slot
                            break

                    regs = self._get_user_regs(pid)
                    caller_ip = regs["rip"] if regs else 0

                    # Disassemble at caller_ip
                    code = _read_mem(pid, caller_ip, 15) or b""
                    insn = _try_disasm(caller_ip, code)

                    # Determine watch type for the fired slot
                    slots = self.manager._slots
                    wp_addr = 0
                    access_type = "rw"
                    if fired_slot >= 0 and fired_slot in slots:
                        wp_addr, access_type, _ = slots[fired_slot]

                    hit = WatchpointHit(
                        watchpoint_addr=wp_addr,
                        caller_ip=caller_ip,
                        instruction=insn,
                        thread_id=pid,
                        timestamp=time.time(),
                        access_type=access_type,
                    )
                    if self.hit_callback:
                        self.hit_callback(hit)

                    # Clear DR6 and resume
                    self.manager._write_dr(pid, 6, 0)
                    _ptrace(PTRACE_CONT, pid, 0, 0)
                else:
                    # Forward other signals
                    _ptrace(PTRACE_CONT, pid, 0, sig)

        # Detach
        try:
            _ptrace(PTRACE_DETACH, pid, 0, 0)
        except Exception:
            pass
