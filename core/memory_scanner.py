"""
Memory scanner: first scan, rescan, and all comparison modes.

Internal storage uses numpy arrays (addresses + values) for efficiency:
  - addresses:   np.ndarray[uint64]  — 8 bytes per entry
  - prev_values: np.ndarray[dtype]   — item_size bytes per entry
This allows 2 000 000 entries in ~24 MB for int32 (vs ~300 MB with Python objects).

next_scan uses clustered batch reads: sorts candidate addresses, groups
neighbours within 64 KB into a single read_memory call, then extracts values
at precise offsets.  Typical next_scan on 500k int32 candidates takes <1s.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Callable, Optional

import numpy as np

from .data_types import (
    DataType, numpy_dtype, type_size, is_variable_length, pack, unpack,
    format_value,
)
from .memory_io import get_readable_regions, read_memory, read_memory_chunks


# ── Scan modes ────────────────────────────────────────────────────────────────

class ScanMode(Enum):
    EXACT         = auto()
    GREATER       = auto()
    LESS          = auto()
    BETWEEN       = auto()
    ANY           = auto()
    NOT_EQUAL     = auto()
    CHANGED       = auto()
    UNCHANGED     = auto()
    INCREASED     = auto()
    DECREASED     = auto()
    INCREASED_BY  = auto()
    DECREASED_BY  = auto()


# ── Limits ────────────────────────────────────────────────────────────────────

MAX_RESULTS    = 2_000_000   # max entries stored (numpy, ~24 MB for int32)
CHUNK_SIZE     = 4 * 1024 * 1024   # 4 MB read chunk during first scan
BATCH_GAP      = 64 * 1024        # cluster next-scan reads within 64 KB


# ── ScanEntry (compatibility shim for GUI) ────────────────────────────────────

@dataclass
class ScanEntry:
    address:        int
    previous_bytes: bytes


# ── ScanState ─────────────────────────────────────────────────────────────────

class ScanState:
    """
    Stores scan results as numpy arrays for memory efficiency.
    addresses:   uint64 array, shape (N,)
    prev_values: typed numpy array matching dtype, shape (N,)
    """

    def __init__(self, pid: int, dtype: DataType,
                 addresses: Optional[np.ndarray] = None,
                 prev_values: Optional[np.ndarray] = None,
                 scan_count: int = 0):
        self.pid        = pid
        self.dtype      = dtype
        self.scan_count = scan_count
        np_dt = numpy_dtype(dtype)

        if addresses is None:
            self.addresses   = np.empty(0, dtype=np.uint64)
            self.prev_values = np.empty(0, dtype=np_dt) if np_dt is not None else []
        else:
            self.addresses   = addresses.astype(np.uint64)
            self.prev_values = prev_values if prev_values is not None else \
                np.empty(0, dtype=np_dt)

    @property
    def count(self) -> int:
        return len(self.addresses)

    def iter_entries(self, limit: Optional[int] = None):
        """Yield (address, value_bytes) without creating Python objects."""
        item_size = type_size(self.dtype)
        n = len(self.addresses) if limit is None else min(len(self.addresses), limit)
        for i in range(n):
            addr = int(self.addresses[i])
            raw  = self.prev_values[i].tobytes() if item_size else b""
            yield addr, raw

    def get_entries(self, limit: Optional[int] = None) -> list[ScanEntry]:
        """Return ScanEntry list (for GUI compatibility)."""
        return [ScanEntry(a, r) for a, r in self.iter_entries(limit)]

    # Legacy compat: some GUI code accesses state.entries directly
    @property
    def entries(self) -> list[ScanEntry]:
        return self.get_entries()


# ── Region-level numpy scan ───────────────────────────────────────────────────

def _apply_mask(arr: np.ndarray, mode: ScanMode,
                np_dt, val1: Any, val2: Any) -> np.ndarray:
    if mode == ScanMode.EXACT:
        return arr == np_dt(val1)
    if mode == ScanMode.GREATER:
        return arr > np_dt(val1)
    if mode == ScanMode.LESS:
        return arr < np_dt(val1)
    if mode == ScanMode.BETWEEN:
        return (arr >= np_dt(val1)) & (arr <= np_dt(val2))
    if mode == ScanMode.ANY:
        return np.ones(len(arr), dtype=bool)
    if mode == ScanMode.NOT_EQUAL:
        return arr != np_dt(val1)
    return np.zeros(len(arr), dtype=bool)


def _scan_region_numpy(data: bytes, base_addr: int, dtype: DataType,
                       mode: ScanMode, val1: Any, val2: Any = None,
                       aligned: bool = True,
                       ) -> tuple[np.ndarray, np.ndarray]:
    """
    Scan a bytes buffer and return (address_array, value_array).

    aligned=True  (default): scan only at naturally-aligned offsets, i.e. the
                             starting offset within the chunk that keeps addresses
                             as multiples of item_size.  Matches Cheat Engine's
                             default behaviour and avoids 4x duplicate candidates.
    aligned=False:           scan at every byte offset (slower, more false positives).
    """
    np_dt     = numpy_dtype(dtype)
    item_size = type_size(dtype)
    if len(data) < item_size:
        return np.empty(0, np.uint64), np.empty(0, np_dt)

    mv = memoryview(data)

    if aligned:
        # Only the single shift that makes base_addr+shift a multiple of item_size
        first_aligned = (item_size - (base_addr % item_size)) % item_size
        shifts = [first_aligned]
    else:
        shifts = list(range(item_size))

    all_addrs:  list[np.ndarray] = []
    all_values: list[np.ndarray] = []

    for shift in shifts:
        available = len(data) - shift
        usable    = (available // item_size) * item_size
        if usable <= 0:
            continue
        arr  = np.frombuffer(mv[shift: shift + usable], dtype=np_dt)
        mask = _apply_mask(arr, mode, np_dt, val1, val2)
        idx  = np.where(mask)[0]
        if len(idx) == 0:
            continue
        byte_offsets = shift + idx.astype(np.uint64) * item_size
        all_addrs.append(np.uint64(base_addr) + byte_offsets)
        all_values.append(arr[idx])

    if not all_addrs:
        return np.empty(0, np.uint64), np.empty(0, np_dt)
    return np.concatenate(all_addrs), np.concatenate(all_values)


# ── String / byte-array scanning ──────────────────────────────────────────────

def _scan_region_bytes(data: bytes, base_addr: int,
                       needle: bytes) -> list[tuple[int, bytes]]:
    results, start = [], 0
    while True:
        idx = data.find(needle, start)
        if idx == -1:
            break
        results.append((base_addr + idx, needle))
        start = idx + 1
    return results


# ── first_scan ────────────────────────────────────────────────────────────────

MAX_REGION_SIZE = 256 * 1024 * 1024   # skip regions > 256 MB (textures/assets)


def first_scan(pid: int, dtype: DataType,
               mode: ScanMode, value: Any, value2: Any = None,
               progress_callback: Optional[Callable] = None,
               aligned: bool = True,
               writable_only: bool = True) -> ScanState:
    """
    Full-memory first scan.  Reads every readable region and collects all
    addresses matching (mode, value).  Capped at MAX_RESULTS (2 000 000).

    writable_only=True (default): skips read-only regions (code, assets,
    memory-mapped game files).  This is ~10-100x faster on large games.
    """
    all_regions = get_readable_regions(pid)
    # Skip huge regions (game textures, asset files) and optionally read-only
    regions = [
        r for r in all_regions
        if r.size <= MAX_REGION_SIZE
        and (not writable_only or r.writable)
    ]
    total_bytes = sum(r.size for r in regions)
    done_bytes  = 0
    item_size   = type_size(dtype)
    overlap     = (item_size - 1) if item_size else 0

    if is_variable_length(dtype):
        needle = (str(value).encode("ascii", errors="replace")
                  if dtype == DataType.STRING_ASCII
                  else bytes.fromhex(str(value).replace(" ", "")))
        pairs: list[tuple[int, bytes]] = []
        for region in regions:
            if len(pairs) >= MAX_RESULTS:
                break
            data = read_memory_chunks(pid, region.start, region.size, CHUNK_SIZE)
            if data:
                pairs.extend(_scan_region_bytes(data, region.start, needle))
            done_bytes += region.size
            if progress_callback:
                progress_callback(done_bytes, total_bytes)
        addrs = [p[0] for p in pairs[:MAX_RESULTS]]
        state = ScanState(pid, dtype, scan_count=1)
        state.addresses   = np.array(addrs, dtype=np.uint64)
        state.prev_values = [p[1] for p in pairs[:MAX_RESULTS]]
        return state

    np_dt = numpy_dtype(dtype)
    addr_chunks:  list[np.ndarray] = []
    value_chunks: list[np.ndarray] = []
    total_found = 0

    for region in regions:
        if total_found >= MAX_RESULTS:
            break
        if region.size < item_size:
            continue
        offset = 0
        while offset < region.size and total_found < MAX_RESULTS:
            to_read = min(CHUNK_SIZE + overlap, region.size - offset)
            data = read_memory(pid, region.start + offset, to_read)
            if data and len(data) >= item_size:
                addrs, values = _scan_region_numpy(
                    data, region.start + offset, dtype, mode, value, value2,
                    aligned=aligned)
                if len(addrs):
                    remaining = MAX_RESULTS - total_found
                    addr_chunks.append(addrs[:remaining])
                    value_chunks.append(values[:remaining])
                    total_found += min(len(addrs), remaining)
            advance    = min(CHUNK_SIZE, region.size - offset)
            done_bytes += advance
            offset     += advance
            if progress_callback:
                progress_callback(done_bytes, total_bytes)

    if addr_chunks:
        all_addrs  = np.concatenate(addr_chunks)
        all_values = np.concatenate(value_chunks)
    else:
        all_addrs  = np.empty(0, np.uint64)
        all_values = np.empty(0, np_dt)

    return ScanState(pid, dtype, all_addrs, all_values, scan_count=1)


# ── next_scan ─────────────────────────────────────────────────────────────────

def next_scan(state: ScanState,
              mode: ScanMode, value: Any = None, value2: Any = None,
              progress_callback: Optional[Callable] = None) -> ScanState:
    """
    Filter existing candidates.

    Uses clustered batch reads: sorts addresses, groups neighbours within
    BATCH_GAP (64 KB) into a single read_memory call, then extracts values
    at the exact byte offsets within each cluster.
    This is orders of magnitude faster than one syscall per address.
    """
    pid       = state.pid
    dtype     = state.dtype
    item_size = type_size(dtype)
    np_dt     = numpy_dtype(dtype)

    if is_variable_length(dtype):
        needle = (str(value).encode("ascii", errors="replace")
                  if dtype == DataType.STRING_ASCII
                  else bytes.fromhex(str(value).replace(" ", "")))
        kept_addrs, kept_vals = [], []
        for addr, prev_bytes in state.iter_entries():
            cur = read_memory(pid, addr, len(needle))
            if cur == needle:
                kept_addrs.append(addr)
                kept_vals.append(cur)
        new_state = ScanState(pid, dtype, scan_count=state.scan_count + 1)
        new_state.addresses   = np.array(kept_addrs, dtype=np.uint64)
        new_state.prev_values = kept_vals
        return new_state

    addresses   = state.addresses
    prev_values = state.prev_values
    n = len(addresses)
    if n == 0:
        return ScanState(pid, dtype,
                         np.empty(0, np.uint64), np.empty(0, np_dt),
                         scan_count=state.scan_count + 1)

    # Sort by address for clustering
    sort_idx    = np.argsort(addresses)
    sorted_addrs = addresses[sort_idx]
    sorted_prevs = prev_values[sort_idx]

    # Find cluster boundaries (gap > BATCH_GAP)
    gaps          = np.diff(sorted_addrs.astype(np.int64))
    breaks        = np.where(gaps > BATCH_GAP)[0] + 1
    cluster_starts = np.concatenate([[0], breaks])
    cluster_ends   = np.concatenate([breaks, [n]])

    kept_addrs:  list[np.ndarray] = []
    kept_values: list[np.ndarray] = []
    done = 0

    for cs, ce in zip(cluster_starts, cluster_ends):
        cluster_addrs = sorted_addrs[cs:ce]
        cluster_prevs = sorted_prevs[cs:ce]

        # Read the whole cluster span in one call
        span_start = int(cluster_addrs[0])
        span_end   = int(cluster_addrs[-1]) + item_size
        span_size  = span_end - span_start

        data = read_memory(pid, span_start, span_size)
        if data is None or len(data) < item_size:
            # fallback: read individually
            for i in range(len(cluster_addrs)):
                raw = read_memory(pid, int(cluster_addrs[i]), item_size)
                if raw and len(raw) == item_size:
                    cur_arr = np.frombuffer(raw, dtype=np_dt)
                    if _match(cur_arr[0], cluster_prevs[i],
                              mode, np_dt, value, value2):
                        kept_addrs.append(cluster_addrs[i:i+1])
                        kept_values.append(cur_arr)
            done += len(cluster_addrs)
            if progress_callback:
                progress_callback(done, n)
            continue

        # Vectorised extraction from cluster span
        offsets = (cluster_addrs - span_start).astype(np.intp)
        mv = memoryview(data)
        cur_list: list[Any] = []
        valid_mask = np.zeros(len(offsets), dtype=bool)

        for i, off in enumerate(offsets):
            end = int(off) + item_size
            if end <= len(data):
                val = np.frombuffer(mv[int(off):end], dtype=np_dt)[0]
                cur_list.append(val)
                valid_mask[i] = True
            else:
                cur_list.append(np_dt(0))

        if not any(valid_mask):
            done += len(cluster_addrs)
            if progress_callback:
                progress_callback(done, n)
            continue

        cur_arr  = np.array(cur_list, dtype=np_dt)
        keep     = valid_mask & _match_array(
            cur_arr, cluster_prevs, mode, np_dt, value, value2)

        if np.any(keep):
            kept_addrs.append(cluster_addrs[keep])
            kept_values.append(cur_arr[keep])

        done += len(cluster_addrs)
        if progress_callback and done % 10000 < len(cluster_addrs):
            progress_callback(done, n)

    if kept_addrs:
        new_addrs  = np.concatenate(kept_addrs)
        new_values = np.concatenate(kept_values)
    else:
        new_addrs  = np.empty(0, np.uint64)
        new_values = np.empty(0, np_dt)

    return ScanState(pid, dtype, new_addrs, new_values,
                     scan_count=state.scan_count + 1)


# ── Comparison helpers ────────────────────────────────────────────────────────

def _match(cur, prev, mode: ScanMode, np_dt, val1, val2) -> bool:
    if mode == ScanMode.EXACT:      return bool(cur == np_dt(val1))
    if mode == ScanMode.GREATER:    return bool(cur > np_dt(val1))
    if mode == ScanMode.LESS:       return bool(cur < np_dt(val1))
    if mode == ScanMode.NOT_EQUAL:  return bool(cur != np_dt(val1))
    if mode == ScanMode.BETWEEN:    return bool(np_dt(val1) <= cur <= np_dt(val2))
    if mode == ScanMode.CHANGED:    return bool(cur != prev)
    if mode == ScanMode.UNCHANGED:  return bool(cur == prev)
    if mode == ScanMode.INCREASED:  return bool(cur > prev)
    if mode == ScanMode.DECREASED:  return bool(cur < prev)
    if mode == ScanMode.INCREASED_BY: return bool(cur == prev + np_dt(val1))
    if mode == ScanMode.DECREASED_BY: return bool(cur == prev - np_dt(val1))
    return False


def _match_array(cur: np.ndarray, prev: np.ndarray,
                 mode: ScanMode, np_dt, val1, val2) -> np.ndarray:
    """Vectorised version of _match for a numpy array."""
    if mode == ScanMode.EXACT:      return cur == np_dt(val1)
    if mode == ScanMode.GREATER:    return cur > np_dt(val1)
    if mode == ScanMode.LESS:       return cur < np_dt(val1)
    if mode == ScanMode.NOT_EQUAL:  return cur != np_dt(val1)
    if mode == ScanMode.BETWEEN:    return (cur >= np_dt(val1)) & (cur <= np_dt(val2))
    if mode == ScanMode.CHANGED:    return cur != prev
    if mode == ScanMode.UNCHANGED:  return cur == prev
    if mode == ScanMode.INCREASED:  return cur > prev
    if mode == ScanMode.DECREASED:  return cur < prev
    if mode == ScanMode.INCREASED_BY:  return cur == prev + np_dt(val1)
    if mode == ScanMode.DECREASED_BY:  return cur == prev - np_dt(val1)
    return np.zeros(len(cur), dtype=bool)


# ── Helpers used by GUI ───────────────────────────────────────────────────────

def read_current_value(pid: int, dtype: DataType, address: int) -> Optional[Any]:
    size = 64 if is_variable_length(dtype) else type_size(dtype)
    data = read_memory(pid, address, size)
    if data is None:
        return None
    try:
        return unpack(dtype, data)
    except Exception:
        return None


def read_current_bytes(pid: int, dtype: DataType, address: int) -> Optional[bytes]:
    size = 64 if is_variable_length(dtype) else type_size(dtype)
    return read_memory(pid, address, size)
