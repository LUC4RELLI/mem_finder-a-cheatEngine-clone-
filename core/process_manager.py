"""
Process enumeration, architecture detection, and ptrace attach/detach.
"""
from __future__ import annotations
import ctypes
import ctypes.util
import os
import signal
from dataclasses import dataclass, field
from typing import Optional

import psutil

# ── ptrace constants ───────────────────────────────────────────────────────────
PTRACE_ATTACH   = 16
PTRACE_DETACH   = 17
PTRACE_CONT     = 7

# Load libc for ptrace
_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
_libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long,
                          ctypes.c_void_p, ctypes.c_void_p]
_libc.ptrace.restype = ctypes.c_long


def _ptrace(request: int, pid: int, addr: int = 0, data: int = 0) -> int:
    ret = _libc.ptrace(request, pid,
                       ctypes.c_void_p(addr),
                       ctypes.c_void_p(data))
    return ret


@dataclass
class ProcessInfo:
    pid: int
    name: str
    arch: int          # 32 or 64
    username: str
    cmdline: str = ""

    def label(self) -> str:
        return f"[{self.pid}] {self.name} ({self.arch}-bit)"


def _detect_arch(pid: int) -> int:
    """
    Read ELF header from /proc/PID/exe.
    Byte at offset 4 is EI_CLASS: 1 = ELFCLASS32, 2 = ELFCLASS64.
    Returns 32, 64, or 0 on failure.
    """
    exe_path = f"/proc/{pid}/exe"
    try:
        with open(exe_path, "rb") as f:
            header = f.read(5)
        if len(header) < 5:
            return 0
        # ELF magic: 0x7F 'E' 'L' 'F'
        if header[:4] != b"\x7fELF":
            return 0
        ei_class = header[4]
        if ei_class == 1:
            return 32
        if ei_class == 2:
            return 64
        return 0
    except (PermissionError, FileNotFoundError, OSError):
        return 64  # Default assumption for inaccessible processes


def list_processes() -> list[ProcessInfo]:
    """Return all running processes with architecture info."""
    result: list[ProcessInfo] = []
    for proc in psutil.process_iter(["pid", "name", "username", "cmdline"]):
        try:
            info = proc.info
            pid = info["pid"]
            name = info["name"] or "<unknown>"
            username = info["username"] or ""
            try:
                cmdline = " ".join(info["cmdline"] or [])
            except (psutil.AccessDenied, TypeError):
                cmdline = ""
            arch = _detect_arch(pid)
            result.append(ProcessInfo(
                pid=pid,
                name=name,
                arch=arch if arch in (32, 64) else 64,
                username=username,
                cmdline=cmdline,
            ))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    result.sort(key=lambda p: p.name.lower())
    return result


def get_process(pid: int) -> Optional[ProcessInfo]:
    """Return ProcessInfo for a single PID, or None if it doesn't exist."""
    try:
        proc = psutil.Process(pid)
        with proc.oneshot():
            name = proc.name()
            username = proc.username()
            try:
                cmdline = " ".join(proc.cmdline())
            except psutil.AccessDenied:
                cmdline = ""
        arch = _detect_arch(pid)
        return ProcessInfo(pid=pid, name=name,
                           arch=arch if arch in (32, 64) else 64,
                           username=username, cmdline=cmdline)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def attach(pid: int) -> bool:
    """
    Attach to a process using PTRACE_ATTACH.
    The process will stop; we immediately send PTRACE_CONT to resume it.
    Returns True on success.
    """
    ret = _ptrace(PTRACE_ATTACH, pid)
    if ret != 0:
        errno = ctypes.get_errno()
        raise PermissionError(
            f"PTRACE_ATTACH failed for PID {pid}: errno {errno} "
            f"({'Operation not permitted' if errno == 1 else os.strerror(errno)})"
        )
    # Wait for SIGSTOP
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
    # Resume the process
    _ptrace(PTRACE_CONT, pid, 0, 0)
    return True


def detach(pid: int) -> None:
    """Detach from a ptrace-attached process."""
    _ptrace(PTRACE_DETACH, pid, 0, 0)


def is_process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False
