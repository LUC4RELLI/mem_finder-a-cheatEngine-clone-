"""
Hardware watchpoints via Linux ptrace debug registers (x86_64).

Uses DR0-DR3 for watchpoint addresses and DR7 for configuration.
When a watchpoint fires (SIGTRAP), reads RIP and IMMEDIATELY resumes
the game — all expensive work (disassembly, callbacks) happens after
PTRACE_CONT so the target process is never frozen for more than ~10µs.
"""
from __future__ import annotations
import ctypes
import ctypes.util
import os
import signal
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

# ── ptrace constants ──────────────────────────────────────────────────────────
PTRACE_ATTACH      = 16
PTRACE_DETACH      = 17
PTRACE_CONT        = 7
PTRACE_PEEKUSER    = 3
PTRACE_POKEUSER    = 6
PTRACE_GETREGS     = 12
PTRACE_SEIZE       = 0x4206   # attach without stopping the process
PTRACE_INTERRUPT   = 0x4207   # stop only the ptrace-attached thread (not SIGSTOP)
PTRACE_SETOPTIONS  = 0x4200
PTRACE_GETEVENTMSG = 0x4201

# Options
PTRACE_O_TRACECLONE = 0x00000008   # auto-seize new threads on clone()

# Stop events embedded in wait status
PTRACE_EVENT_CLONE = 3

# x86_64 user struct offsets for debug registers (bytes)
_DR_BASE_OFFSET = 848
DR_OFFSETS = {
    0: _DR_BASE_OFFSET + 0 * 8,   # DR0 = 848
    1: _DR_BASE_OFFSET + 1 * 8,   # DR1 = 856
    2: _DR_BASE_OFFSET + 2 * 8,   # DR2 = 864
    3: _DR_BASE_OFFSET + 3 * 8,   # DR3 = 872
    6: _DR_BASE_OFFSET + 6 * 8,   # DR6 = 896
    7: _DR_BASE_OFFSET + 7 * 8,   # DR7 = 912
}

_COND_EXECUTE   = 0b00
_COND_WRITE     = 0b01
_COND_READWRITE = 0b11
_SIZE_MAP = {1: 0b00, 2: 0b01, 4: 0b11, 8: 0b10}

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
_libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long,
                          ctypes.c_void_p, ctypes.c_void_p]
_libc.ptrace.restype = ctypes.c_long


def _ptrace(request: int, pid: int, addr: int = 0, data: int = 0) -> int:
    return _libc.ptrace(
        ctypes.c_long(request), ctypes.c_long(pid),
        ctypes.c_void_p(addr), ctypes.c_void_p(data),
    )


def _get_tids(pid: int) -> list[int]:
    """Return all thread IDs (TIDs) for the given process."""
    try:
        return [int(t) for t in os.listdir(f"/proc/{pid}/task")]
    except (FileNotFoundError, PermissionError):
        return [pid]


# ── Capstone — initialised once at module load ────────────────────────────────

_cs = None

def _get_cs():
    global _cs
    if _cs is None:
        try:
            import capstone
            _cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            _cs.detail = False
        except Exception:
            _cs = False   # capstone unavailable
    return _cs


def _disasm(ip: int, code: bytes) -> str:
    cs = _get_cs()
    if not cs:
        return "<capstone unavailable>"
    try:
        for insn in cs.disasm(code, ip):
            return f"{insn.mnemonic} {insn.op_str}"
    except Exception:
        pass
    return "<disasm failed>"


# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class WatchpointHit:
    watchpoint_addr: int
    caller_ip:       int
    instruction:     str
    thread_id:       int
    timestamp:       float
    access_type:     str

    def format(self) -> str:
        ts = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        ms = int((self.timestamp % 1) * 1000)
        return (
            f"[{ts}.{ms:03d}] WP@0x{self.watchpoint_addr:X} "
            f"accessed by 0x{self.caller_ip:X} ({self.instruction}) "
            f"tid={self.thread_id}"
        )


# ── WatchpointManager ─────────────────────────────────────────────────────────

class WatchpointManager:
    MAX_SLOTS = 4

    def __init__(self, pid: int,
                 hit_callback: Optional[Callable[[WatchpointHit], None]] = None):
        self.pid = pid
        self.hit_callback = hit_callback
        self._slots: dict[int, tuple[int, str, int]] = {}
        self._thread: Optional[_WatchThread] = None
        self._lock = threading.Lock()

    def _find_free_slot(self) -> Optional[int]:
        for i in range(self.MAX_SLOTS):
            if i not in self._slots:
                return i
        return None

    def _write_dr(self, tid: int, dr_num: int, value: int) -> bool:
        offset = DR_OFFSETS.get(dr_num)
        if offset is None:
            return False
        return _ptrace(PTRACE_POKEUSER, tid, offset, value) == 0

    def _read_dr(self, tid: int, dr_num: int) -> int:
        offset = DR_OFFSETS.get(dr_num)
        if offset is None:
            return 0
        ret = _ptrace(PTRACE_PEEKUSER, tid, offset, 0)
        return ret & 0xFFFFFFFFFFFFFFFF if ret != -1 else 0

    def _build_dr7(self) -> int:
        dr7 = 0
        for slot, (addr, wtype, size) in self._slots.items():
            dr7 |= (1 << (slot * 2))
            cond = (_COND_EXECUTE if wtype == "exec"
                    else _COND_WRITE if wtype == "write"
                    else _COND_READWRITE)
            size_code = _SIZE_MAP.get(size, _SIZE_MAP[4])
            shift = 16 + slot * 4
            dr7 |= (cond << shift) | (size_code << (shift + 2))
        return dr7

    def _apply_watchpoints_to_tid(self, tid: int) -> None:
        dr7 = self._build_dr7()
        for slot, (addr, _, _) in self._slots.items():
            self._write_dr(tid, slot, addr)
        self._write_dr(tid, 6, 0)
        self._write_dr(tid, 7, dr7)

    def start(self) -> None:
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
        with self._lock:
            if self._thread:
                self._thread.stop()
                self._thread.join(timeout=3.0)
                self._thread = None

    def add_watchpoint(self, addr: int, watch_type: str = "rw",
                       size: int = 4) -> bool:
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
        with self._lock:
            return [(s, a, t, z) for s, (a, t, z) in self._slots.items()]

    @property
    def slot_count(self) -> int:
        return len(self._slots)


# ── Watch thread ──────────────────────────────────────────────────────────────

class _WatchThread(threading.Thread):
    # Maximum watchpoint hits processed per second (avoids freezing fast games)
    _MAX_HITS_PER_SEC = 50

    def __init__(self, pid: int, manager: WatchpointManager,
                 hit_callback: Optional[Callable[[WatchpointHit], None]]):
        super().__init__(name=f"watchpoint-{pid}", daemon=True)
        self.pid = pid
        self.manager = manager
        self.hit_callback = hit_callback
        self._stop_event = threading.Event()
        self._apply_event = threading.Event()
        # Rate limiting
        self._hit_times: list[float] = []

    def stop(self) -> None:
        self._stop_event.set()

    def request_apply(self) -> None:
        self._apply_event.set()

    def _rate_ok(self) -> bool:
        """Return True if we should process this hit (rate limit check)."""
        now = time.monotonic()
        cutoff = now - 1.0
        self._hit_times = [t for t in self._hit_times if t > cutoff]
        if len(self._hit_times) >= self._MAX_HITS_PER_SEC:
            return False
        self._hit_times.append(now)
        return True

    def _get_rip(self, pid: int) -> int:
        class _Regs(ctypes.Structure):
            _fields_ = [
                ("r15", ctypes.c_ulonglong), ("r14", ctypes.c_ulonglong),
                ("r13", ctypes.c_ulonglong), ("r12", ctypes.c_ulonglong),
                ("rbp", ctypes.c_ulonglong), ("rbx", ctypes.c_ulonglong),
                ("r11", ctypes.c_ulonglong), ("r10", ctypes.c_ulonglong),
                ("r9",  ctypes.c_ulonglong), ("r8",  ctypes.c_ulonglong),
                ("rax", ctypes.c_ulonglong), ("rcx", ctypes.c_ulonglong),
                ("rdx", ctypes.c_ulonglong), ("rsi", ctypes.c_ulonglong),
                ("rdi", ctypes.c_ulonglong), ("orig_rax", ctypes.c_ulonglong),
                ("rip", ctypes.c_ulonglong), ("cs",  ctypes.c_ulonglong),
                ("eflags", ctypes.c_ulonglong), ("rsp", ctypes.c_ulonglong),
                ("ss",  ctypes.c_ulonglong), ("fs_base", ctypes.c_ulonglong),
                ("gs_base", ctypes.c_ulonglong), ("ds", ctypes.c_ulonglong),
                ("es",  ctypes.c_ulonglong), ("fs",  ctypes.c_ulonglong),
                ("gs",  ctypes.c_ulonglong),
            ]
        regs = _Regs()
        if _ptrace(PTRACE_GETREGS, pid, 0, ctypes.addressof(regs)) == 0:
            return regs.rip
        return 0

    def run(self) -> None:
        from .memory_io import read_memory as _read_mem

        pid = self.pid

        # --- Attach to main thread --------------------------------------------
        # PTRACE_SEIZE attaches without sending SIGSTOP — the game keeps running.
        # We also request PTRACE_O_TRACECLONE so the kernel automatically seizes
        # any new thread the process spawns and notifies us via SIGTRAP.
        seized_main = False
        ret = _ptrace(PTRACE_SEIZE, pid)
        if ret == 0:
            seized_main = True
            _ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACECLONE)
        else:
            # Fall back to classic PTRACE_ATTACH
            if _ptrace(PTRACE_ATTACH, pid) != 0:
                return
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass

        # --- Apply watchpoints to ALL existing threads at attach time ---------
        self._attach_all_threads(pid, seized_main)

        while not self._stop_event.is_set():
            # Re-apply watchpoints if slots changed (add/remove)
            if self._apply_event.is_set():
                self._apply_event.clear()
                self._attach_all_threads(pid, seized=True)

            # Wait for events from ANY traced thread (not just the main PID)
            try:
                child_pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break

            if child_pid == 0:
                time.sleep(0.01)
                continue

            # Main process exited
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                if child_pid == pid:
                    break
                continue   # a worker thread exited; keep monitoring

            if not os.WIFSTOPPED(status):
                continue

            sig       = os.WSTOPSIG(status)
            event     = (status >> 16) & 0xFF   # upper byte encodes ptrace event
            traced_tid = child_pid              # the actual TID that stopped

            # ── New thread cloned — apply watchpoints and continue it ─────────
            if sig == signal.SIGTRAP and event == PTRACE_EVENT_CLONE:
                new_tid_long = ctypes.c_ulong(0)
                _ptrace(PTRACE_GETEVENTMSG, traced_tid, 0,
                        ctypes.addressof(new_tid_long))
                new_tid = int(new_tid_long.value)
                _ptrace(PTRACE_CONT, traced_tid, 0, 0)
                # The new thread starts in stopped state; wait for it then set DRs
                try:
                    os.waitpid(new_tid, 0)
                except ChildProcessError:
                    pass
                try:
                    self.manager._apply_watchpoints_to_tid(new_tid)
                except Exception:
                    pass
                _ptrace(PTRACE_CONT, new_tid, 0, 0)
                continue

            if sig == signal.SIGTRAP:
                # ── CRITICAL: minimise stop time ──────────────────────────────
                # 1. Read which watchpoint fired (DR6 of the stopped thread)
                dr6 = self.manager._read_dr(traced_tid, 6)
                fired_slot = next(
                    (s for s in range(4) if dr6 & (1 << s)), -1)

                # 2. Read RIP
                caller_ip = self._get_rip(traced_tid)

                # 3. Clear DR6
                self.manager._write_dr(traced_tid, 6, 0)

                # 4. RESUME THE THREAD IMMEDIATELY — before any slow work
                _ptrace(PTRACE_CONT, traced_tid, 0, 0)
                # ── Thread is running again ───────────────────────────────────

                if not self._rate_ok():
                    continue

                # 5. Expensive work runs while the game is already running
                slots = self.manager._slots
                wp_addr = 0
                access_type = "rw"
                if fired_slot >= 0 and fired_slot in slots:
                    wp_addr, access_type, _ = slots[fired_slot]

                code = _read_mem(pid, caller_ip, 15) or b""
                insn = _disasm(caller_ip, code)

                hit = WatchpointHit(
                    watchpoint_addr=wp_addr,
                    caller_ip=caller_ip,
                    instruction=insn,
                    thread_id=traced_tid,
                    timestamp=time.time(),
                    access_type=access_type,
                )
                if self.hit_callback:
                    self.hit_callback(hit)

            else:
                # Forward all other signals without delay
                _ptrace(PTRACE_CONT, traced_tid, 0, sig)

        # Detach from every thread we may have attached to
        for tid in _get_tids(pid):
            try:
                _ptrace(PTRACE_DETACH, tid, 0, 0)
            except Exception:
                pass

    # ── Helper: interrupt all threads, set DRs, resume ───────────────────────

    def _attach_all_threads(self, pid: int, seized: bool) -> None:
        """
        Apply current watchpoints to every thread in the process.

        For each TID:
          - If not yet traced: PTRACE_SEIZE it.
          - PTRACE_INTERRUPT to stop it momentarily.
          - Write DR0-DR3 + DR7.
          - PTRACE_CONT to resume.
        """
        for tid in _get_tids(pid):
            try:
                # Always attempt to seize non-main threads.
                # PTRACE_SEIZE on an already-seized thread returns an error —
                # that's fine; we just need it seized before PTRACE_INTERRUPT.
                if tid != pid:
                    _ptrace(PTRACE_SEIZE, tid)

                ret = _ptrace(PTRACE_INTERRUPT, tid)
                if ret != 0:
                    continue  # couldn't interrupt this thread, skip it

                # Use WNOHANG + timeout instead of blocking forever.
                # An unresponsive thread would otherwise freeze the whole process.
                deadline = time.monotonic() + 0.5
                stopped = False
                while time.monotonic() < deadline:
                    try:
                        r, _ = os.waitpid(tid, os.WNOHANG)
                        if r == tid:
                            stopped = True
                            break
                    except ChildProcessError:
                        stopped = True
                        break
                    time.sleep(0.005)

                if not stopped:
                    continue  # thread didn't stop in time, skip

                self.manager._apply_watchpoints_to_tid(tid)
                _ptrace(PTRACE_CONT, tid, 0, 0)
            except Exception:
                pass
