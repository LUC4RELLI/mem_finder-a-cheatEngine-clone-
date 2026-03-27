"""
Low-level memory reading/writing via process_vm_readv / process_vm_writev.
Also provides /proc/PID/maps parsing.
"""
from __future__ import annotations
import ctypes
import ctypes.util
import os
from dataclasses import dataclass
from typing import Optional

# ── syscall numbers (x86_64 Linux) ────────────────────────────────────────────
SYS_PROCESS_VM_READV  = 310
SYS_PROCESS_VM_WRITEV = 311

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

# ── iovec struct ───────────────────────────────────────────────────────────────
class _Iovec(ctypes.Structure):
    _fields_ = [
        ("iov_base", ctypes.c_void_p),
        ("iov_len",  ctypes.c_size_t),
    ]


def _read_proc_mem(pid: int, addr: int, size: int) -> Optional[bytes]:
    """Fallback: read via /proc/pid/mem using pread."""
    try:
        fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
        try:
            data = os.pread(fd, size, addr)
            return data if len(data) == size else None
        finally:
            os.close(fd)
    except OSError:
        return None


def read_memory(pid: int, addr: int, size: int) -> Optional[bytes]:
    """
    Read `size` bytes from the memory of `pid` starting at `addr`.
    Tries process_vm_readv first, falls back to /proc/pid/mem.
    Returns bytes on success, None on failure.
    """
    if size <= 0:
        return b""
    buf = (ctypes.c_char * size)()
    local = _Iovec(iov_base=ctypes.cast(buf, ctypes.c_void_p),
                   iov_len=size)
    remote = _Iovec(iov_base=ctypes.c_void_p(addr),
                    iov_len=size)
    ret = _libc.syscall(SYS_PROCESS_VM_READV,
                        ctypes.c_long(pid),
                        ctypes.byref(local), ctypes.c_ulong(1),
                        ctypes.byref(remote), ctypes.c_ulong(1),
                        ctypes.c_ulong(0))
    if ret == size:
        return bytes(buf[:ret])
    # Fallback to /proc/pid/mem
    return _read_proc_mem(pid, addr, size)


def write_memory(pid: int, addr: int, data: bytes) -> bool:
    """
    Write `data` into `pid`'s memory at `addr`.
    Returns True on success.
    """
    if not data:
        return True
    size = len(data)
    buf = (ctypes.c_char * size)(*data)
    local = _Iovec(iov_base=ctypes.cast(buf, ctypes.c_void_p),
                   iov_len=size)
    remote = _Iovec(iov_base=ctypes.c_void_p(addr),
                    iov_len=size)
    ret = _libc.syscall(SYS_PROCESS_VM_WRITEV,
                        ctypes.c_long(pid),
                        ctypes.byref(local), ctypes.c_ulong(1),
                        ctypes.byref(remote), ctypes.c_ulong(1),
                        ctypes.c_ulong(0))
    return ret == size


def read_memory_chunks(pid: int, addr: int, size: int,
                       chunk_size: int = 1024 * 1024) -> bytes:
    """
    Read a large region in chunks. Returns as many bytes as could be read.
    """
    result = bytearray()
    offset = 0
    while offset < size:
        to_read = min(chunk_size, size - offset)
        chunk = read_memory(pid, addr + offset, to_read)
        if chunk is None or len(chunk) == 0:
            break
        result.extend(chunk)
        offset += len(chunk)
        if len(chunk) < to_read:
            break
    return bytes(result)


# ── Memory map parsing ─────────────────────────────────────────────────────────

@dataclass
class MemoryRegion:
    start:      int
    end:        int
    readable:   bool
    writable:   bool
    executable: bool
    private:    bool
    offset:     int
    device:     str
    inode:      int
    name:       str   # path or [heap], [stack], etc.

    @property
    def size(self) -> int:
        return self.end - self.start

    def __repr__(self) -> str:
        flags = ("r" if self.readable else "-"
                 + "w" if self.writable else "-"
                 + "x" if self.executable else "-")
        return (f"MemoryRegion(0x{self.start:016x}-0x{self.end:016x} "
                f"{flags} {self.name!r})")


def get_memory_maps(pid: int) -> list[MemoryRegion]:
    """Parse /proc/PID/maps and return all memory regions."""
    regions: list[MemoryRegion] = []
    maps_path = f"/proc/{pid}/maps"
    try:
        with open(maps_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) < 5:
                    continue
                addr_range = parts[0].split("-")
                start = int(addr_range[0], 16)
                end   = int(addr_range[1], 16)
                perms = parts[1]
                offset = int(parts[2], 16)
                device = parts[3]
                inode  = int(parts[4])
                name   = parts[5] if len(parts) > 5 else ""

                regions.append(MemoryRegion(
                    start=start, end=end,
                    readable=("r" in perms),
                    writable=("w" in perms),
                    executable=("x" in perms),
                    private=("p" in perms),
                    offset=offset,
                    device=device,
                    inode=inode,
                    name=name,
                ))
    except (FileNotFoundError, PermissionError):
        pass
    return regions


def get_readable_regions(pid: int,
                         skip_special: bool = True) -> list[MemoryRegion]:
    """
    Return only readable regions. Optionally skip vdso/vsyscall/vvar.
    """
    skip_names = {"[vdso]", "[vsyscall]", "[vvar]"}
    return [
        r for r in get_memory_maps(pid)
        if r.readable
        and (not skip_special or r.name not in skip_names)
    ]


def get_module_bases(pid: int) -> dict[str, int]:
    """
    Return mapping of module/file name → lowest base address.
    Used by pointer scanner to identify static bases.
    """
    bases: dict[str, int] = {}
    for r in get_memory_maps(pid):
        if r.name and not r.name.startswith("["):
            basename = os.path.basename(r.name)
            if basename not in bases or r.start < bases[basename]:
                bases[basename] = r.start
    return bases


def address_to_module(pid: int, addr: int) -> Optional[tuple[str, int]]:
    """
    Given an address, return (module_name, offset_within_module) or None.
    """
    for r in get_memory_maps(pid):
        if r.start <= addr < r.end and r.name and not r.name.startswith("["):
            basename = os.path.basename(r.name)
            # Find the base load address of this module
            module_base = r.start - r.offset
            offset = addr - module_base
            return (basename, offset)
    return None
