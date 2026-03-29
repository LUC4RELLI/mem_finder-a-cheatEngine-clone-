"""
Pointer chain scanner.

Given a target address, finds all static pointer chains (base_module + offsets)
that resolve to the target address. Uses a backwards BFS approach:
- Level 0: the target address itself
- Level N: all addresses that hold a pointer to any Level N-1 address (±range)
At each level, chains anchored to a static module base are recorded.

Performance notes:
- Only writable regions are scanned (skips read-only code/assets/textures).
- Regions are processed in SCAN_CHUNK-sized sub-chunks to bound RAM usage.
- A short sleep between sub-chunks prevents CPU saturation and system freeze.
- Memory maps are cached once per scan; _classify_address does NOT re-read them.
"""
from __future__ import annotations
import os
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

import numpy as np

from .memory_io import (
    get_memory_maps, get_module_bases, read_memory_chunks, MemoryRegion,
)

# ── Performance tuning ────────────────────────────────────────────────────────
SCAN_CHUNK    = 64 * 1024 * 1024   # 64 MB: max bytes loaded into RAM per pass
_CHUNK_SLEEP  = 0.002              # 2 ms yield between sub-chunks (prevents freeze)
_SKIP_NAMES   = {"[vdso]", "[vsyscall]", "[vvar]"}


@dataclass
class PointerChain:
    """
    Represents a resolved pointer chain.
    base_module: name of the module (e.g. "game.exe", "libSDL2.so")
    base_offset: offset within the module's base address
    offsets: list of dereference offsets to reach the target
    final_address: the resolved address (should match target ± range)
    """
    base_module:  str
    base_offset:  int
    offsets:      list[int]
    final_address: int

    def display(self) -> str:
        chain = f'["{self.base_module}"+0x{self.base_offset:X}]'
        for off in self.offsets:
            sign = "+" if off >= 0 else "-"
            chain += f" → {sign}0x{abs(off):X}"
        chain += f" = 0x{self.final_address:X}"
        return chain


class PointerScanner:
    """
    Scans for pointer chains leading to a target address.

    Parameters:
        pid:           target process PID
        target_addr:   the memory address we want to find a chain for
        max_depth:     maximum number of pointer hops (default 5)
        pointer_range: accept pointers to target±range (default 0x500)
        ptr_size:      4 for 32-bit processes, 8 for 64-bit
        max_results:   cap on returned chains
    """

    def __init__(
            self, pid: int, target_addr: int,
            max_depth: int = 5,
            pointer_range: int = 0x500,
            ptr_size: int = 8,
            max_results: int = 200,
            progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ):
        self.pid = pid
        self.target_addr = target_addr
        self.max_depth = max_depth
        self.pointer_range = pointer_range
        self.ptr_size = ptr_size
        self.max_results = max_results
        self.progress_callback = progress_callback
        self._stop_event = threading.Event()

        self.chains: list[PointerChain] = []
        self._module_bases: dict[str, int] = {}  # name -> base address

    def stop(self) -> None:
        self._stop_event.set()

    def scan(self) -> list[PointerChain]:
        """
        Run the pointer scan synchronously. Returns list of PointerChain.
        """
        self._stop_event.clear()
        self.chains = []
        self._module_bases = get_module_bases(self.pid)

        # Cache maps once — _classify_address uses self._maps, never re-reads.
        self._maps: list[MemoryRegion] = get_memory_maps(self.pid)

        # Invert: base_address -> module_name for quick lookup
        self._addr_to_module: dict[int, str] = {
            v: k for k, v in self._module_bases.items()
        }

        # Only scan writable+readable regions (heap, stack, data segments).
        # Skipping read-only regions (code, mapped textures/assets) is the
        # single most important performance win — it cuts scan size by ~90 %.
        scan_regions = [
            r for r in self._maps
            if r.readable
            and r.writable
            and r.name not in _SKIP_NAMES
        ]

        if self.progress_callback:
            self.progress_callback(0, self.max_depth, "Loading memory regions")

        # BFS backwards:
        # current_targets: set of addresses to find pointers TO
        # Each entry: target_addr -> offset_that_was_added_to_reach_original_target
        current_targets: dict[int, int] = {
            self.target_addr: 0
        }

        # chain_map: pointer_address -> list of (chain_suffix: list[int])
        # chain_suffix[0] = offset added to pointer value to reach the address
        chain_map: dict[int, list[list[int]]] = {}

        for depth in range(self.max_depth):
            if self._stop_event.is_set():
                break
            if self.progress_callback:
                self.progress_callback(depth, self.max_depth,
                                       f"Scanning depth {depth+1}/{self.max_depth} "
                                       f"({len(current_targets)} targets)")

            next_targets: dict[int, int] = {}
            new_chain_map: dict[int, list[list[int]]] = {}

            found_ptrs = self._find_pointers_to(
                scan_regions, current_targets, self.pointer_range,
            )

            if not found_ptrs:
                break

            for ptr_addr, (target, offset) in found_ptrs.items():
                if self._stop_event.is_set():
                    break

                # Build chain suffixes for this pointer
                if depth == 0:
                    suffix = [offset]
                else:
                    # suffix = [offset] + all previous suffixes from this target
                    prev_suffixes = chain_map.get(target, [[]])
                    suffix_list = [[offset] + s for s in prev_suffixes]
                    new_chain_map[ptr_addr] = suffix_list

                    # Check if ptr_addr is a static base
                    module_name, module_off = self._classify_address(ptr_addr)
                    if module_name:
                        for s in suffix_list:
                            if len(self.chains) >= self.max_results:
                                break
                            self.chains.append(PointerChain(
                                base_module=module_name,
                                base_offset=module_off,
                                offsets=s,
                                final_address=self.target_addr,
                            ))
                    next_targets[ptr_addr] = offset
                    continue

                # depth == 0: record initial suffix
                new_chain_map[ptr_addr] = [suffix]
                module_name, module_off = self._classify_address(ptr_addr)
                if module_name:
                    if len(self.chains) < self.max_results:
                        self.chains.append(PointerChain(
                            base_module=module_name,
                            base_offset=module_off,
                            offsets=suffix,
                            final_address=self.target_addr,
                        ))
                next_targets[ptr_addr] = offset

            chain_map = new_chain_map
            current_targets = next_targets

            if len(self.chains) >= self.max_results:
                break

        if self.progress_callback:
            self.progress_callback(self.max_depth, self.max_depth,
                                   f"Done — {len(self.chains)} chains found")
        return self.chains

    def _find_pointers_to(
            self,
            regions: list[MemoryRegion],
            targets: dict[int, int],
            search_range: int,
    ) -> dict[int, tuple[int, int]]:
        """
        Scan all writable regions for pointer values in targets±search_range.
        Returns: {ptr_address: (target_addr_matched, offset_to_target)}

        Key performance choices:
        - Regions are split into SCAN_CHUNK sub-chunks so we never hold more
          than 32 MB of foreign process memory in RAM at once.
        - A short sleep after each sub-chunk yields the CPU scheduler and
          prevents the system from feeling frozen.
        - A single combined-mask numpy pass per sub-chunk (instead of one pass
          per target) keeps the hot loop vectorised.
        """
        ptr_size = self.ptr_size
        np_dt    = np.uint64 if ptr_size == 8 else np.uint32

        target_list = list(targets.keys())
        if not target_list:
            return {}

        # Pre-compute search ranges as plain Python ints to avoid uint64
        # wrap-around when target_addr < search_range.
        ranges = [
            (max(0, t - search_range), t + search_range, t)
            for t in target_list
        ]
        r_min = [r[0] for r in ranges]
        r_max = [r[1] for r in ranges]
        r_tgt = [r[2] for r in ranges]

        # Pre-build numpy arrays once (shared across all chunks)
        r_min_arr = np.array(r_min, dtype=np.uint64)
        r_max_arr = np.array(r_max, dtype=np.uint64)

        result: dict[int, tuple[int, int]] = {}

        for region in regions:
            if self._stop_event.is_set():
                break
            if region.size < ptr_size:
                continue

            # ── Process region in SCAN_CHUNK sub-chunks ───────────────────────
            offset = 0
            while offset < region.size:
                if self._stop_event.is_set():
                    break

                chunk_size = min(SCAN_CHUNK, region.size - offset)
                abs_start  = region.start + offset

                data = read_memory_chunks(self.pid, abs_start, chunk_size)
                offset += chunk_size

                if not data or len(data) < ptr_size:
                    time.sleep(_CHUNK_SLEEP)
                    continue

                usable = (len(data) // ptr_size) * ptr_size
                arr    = np.frombuffer(data[:usable], dtype=np_dt)

                # Combined mask: one numpy pass to flag any value in any range.
                combined = np.zeros(len(arr), dtype=bool)
                for mn, mx in zip(r_min, r_max):
                    combined |= (arr >= np_dt(mn)) & (arr <= np_dt(mx))

                hit_idxs = np.where(combined)[0]
                if len(hit_idxs):
                    hit_vals = arr[hit_idxs]
                    hit_addrs = abs_start + hit_idxs.astype(np.uint64) * ptr_size
                    for j in range(len(hit_idxs)):
                        val      = hit_vals[j]
                        ptr_addr = int(hit_addrs[j])
                        # Vectorised search across targets
                        k_match = np.where((r_min_arr <= val) & (val <= r_max_arr))[0]
                        if len(k_match):
                            k = int(k_match[0])
                            result[ptr_addr] = (r_tgt[k], r_tgt[k] - int(val))

                # Yield CPU — prevents system freeze on large heaps
                time.sleep(_CHUNK_SLEEP)

        return result

    def _classify_address(self, addr: int) -> tuple[str, int]:
        """
        Return (module_name, offset_from_module_base) if the address
        falls within a loaded module's mapped region. Otherwise ("", 0).

        Uses self._maps (cached at scan start) — never re-reads /proc/pid/maps.
        """
        for r in self._maps:
            if r.start <= addr < r.end and r.name and not r.name.startswith("["):
                basename = os.path.basename(r.name)
                base = self._module_bases.get(basename, r.start)
                return (basename, addr - base)
        return ("", 0)
