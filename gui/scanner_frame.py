"""
Memory scanner frame: type selection, scan modes, and results.
"""
from __future__ import annotations
import threading
import tkinter as tk
from tkinter import messagebox
from typing import Optional

import customtkinter as ctk

from core.data_types import DataType, display_name, ALL_TYPES, unpack, format_value, type_size, is_variable_length
from core.memory_io import read_memory, make_module_resolver
from core.memory_scanner import (
    ScanMode, ScanState, ScanEntry, first_scan, next_scan, MAX_RESULTS,
)


_SCAN_MODE_LABELS = {
    ScanMode.EXACT:        "Exact Value",
    ScanMode.GREATER:      "Greater Than",
    ScanMode.LESS:         "Less Than",
    ScanMode.BETWEEN:      "Between",
    ScanMode.ANY:          "Any Value (wildcard)",
    ScanMode.NOT_EQUAL:    "Not Equal",
    ScanMode.CHANGED:      "Changed",
    ScanMode.UNCHANGED:    "Unchanged",
    ScanMode.INCREASED:    "Increased",
    ScanMode.DECREASED:    "Decreased",
    ScanMode.INCREASED_BY: "Increased By",
    ScanMode.DECREASED_BY: "Decreased By",
}

_FIRST_SCAN_MODES = [
    ScanMode.EXACT, ScanMode.GREATER, ScanMode.LESS,
    ScanMode.BETWEEN, ScanMode.ANY, ScanMode.NOT_EQUAL,
]

_NEXT_SCAN_MODES = [
    ScanMode.EXACT, ScanMode.GREATER, ScanMode.LESS,
    ScanMode.BETWEEN, ScanMode.NOT_EQUAL,
    ScanMode.CHANGED, ScanMode.UNCHANGED,
    ScanMode.INCREASED, ScanMode.DECREASED,
    ScanMode.INCREASED_BY, ScanMode.DECREASED_BY,
]

# How many results to show and refresh live
_DISPLAY_LIMIT = 2000
_LIVE_REFRESH_MS = 500


class ScannerFrame(ctk.CTkFrame):
    def __init__(self, parent, app, **kwargs):
        super().__init__(parent, **kwargs)
        self.app = app
        self._scan_state: Optional[ScanState] = None
        self._prev_scan_state: Optional[ScanState] = None
        self._scanning = False
        self._build_ui()
        self._schedule_live_refresh()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        from tkinter import ttk

        row1 = ctk.CTkFrame(self, fg_color="transparent")
        row1.pack(fill="x", padx=8, pady=(8, 4))

        ctk.CTkLabel(row1, text="Value Type:").pack(side="left", padx=(0, 4))
        self._type_var = tk.StringVar(value=display_name(DataType.INT32))
        self._type_menu = ctk.CTkOptionMenu(
            row1, variable=self._type_var,
            values=[display_name(dt) for dt in ALL_TYPES],
            width=160, command=self._on_type_change,
        )
        self._type_menu.pack(side="left", padx=(0, 12))

        ctk.CTkLabel(row1, text="Scan Type:").pack(side="left", padx=(0, 4))
        self._mode_var = tk.StringVar(value=_SCAN_MODE_LABELS[ScanMode.EXACT])
        self._mode_menu = ctk.CTkOptionMenu(
            row1, variable=self._mode_var,
            values=[_SCAN_MODE_LABELS[m] for m in _FIRST_SCAN_MODES],
            width=180, command=self._on_mode_change,
        )
        self._mode_menu.pack(side="left")

        row2 = ctk.CTkFrame(self, fg_color="transparent")
        row2.pack(fill="x", padx=8, pady=4)

        ctk.CTkLabel(row2, text="Value:").pack(side="left", padx=(0, 4))
        self._val1_var = tk.StringVar()
        self._val1_entry = ctk.CTkEntry(row2, textvariable=self._val1_var, width=140)
        self._val1_entry.pack(side="left", padx=(0, 4))
        self._val1_entry.bind("<Return>", lambda _: self._do_scan())

        self._to_label = ctk.CTkLabel(row2, text="to")
        self._val2_var = tk.StringVar()
        self._val2_entry = ctk.CTkEntry(row2, textvariable=self._val2_var, width=100)

        row3 = ctk.CTkFrame(self, fg_color="transparent")
        row3.pack(fill="x", padx=8, pady=4)

        self._first_btn = ctk.CTkButton(
            row3, text="First Scan", width=110, command=self._do_first_scan)
        self._first_btn.pack(side="left", padx=(0, 6))

        self._next_btn = ctk.CTkButton(
            row3, text="Next Scan", width=110,
            command=self._do_next_scan, state="disabled")
        self._next_btn.pack(side="left", padx=(0, 6))

        self._new_btn = ctk.CTkButton(
            row3, text="New Scan", width=110,
            command=self._do_new_scan, state="disabled",
            fg_color="#555555")
        self._new_btn.pack(side="left", padx=(0, 6))

        self._undo_btn = ctk.CTkButton(
            row3, text="Undo Scan", width=100,
            command=self._undo_scan, state="disabled",
            fg_color="#553355")
        self._undo_btn.pack(side="left", padx=(0, 12))

        self._add_all_btn = ctk.CTkButton(
            row3, text="Add All to Table", width=130,
            command=self._add_all_to_table, state="disabled",
            fg_color="#2a6099")
        self._add_all_btn.pack(side="left", padx=(0, 12))

        self._aligned_var = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(row3, text="Aligned",
                        variable=self._aligned_var,
                        width=90).pack(side="left")

        self._writable_var = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(row3, text="Writable only",
                        variable=self._writable_var,
                        width=120).pack(side="left", padx=(6, 0))

        self._progress = ctk.CTkProgressBar(self, mode="determinate")
        self._progress.pack(fill="x", padx=8, pady=(0, 4))
        self._progress.set(0)

        self._status = ctk.CTkLabel(
            self, text="No scan performed.",
            font=ctk.CTkFont(size=11), anchor="w")
        self._status.pack(fill="x", padx=8, pady=(0, 2))

        style = ttk.Style()
        style.theme_use("default")
        style.configure("Scan.Treeview",
                         background="#1e1e1e", foreground="white",
                         rowheight=20, fieldbackground="#1e1e1e", borderwidth=0)
        style.configure("Scan.Treeview.Heading",
                         background="#2a2a2a", foreground="#aaaaaa")
        style.map("Scan.Treeview", background=[("selected", "#1f538d")])

        res_frame = ctk.CTkFrame(self)
        res_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self._results = ttk.Treeview(
            res_frame, columns=("address", "module", "value"),
            show="headings", style="Scan.Treeview", selectmode="extended")
        self._results.heading("address", text="Address")
        self._results.heading("module",  text="Module")
        self._results.heading("value",   text="Value  ↺")
        self._results.column("address", width=140, anchor="w")
        self._results.column("module",  width=190, anchor="w")
        self._results.column("value",   width=110, anchor="w")

        vsb = ttk.Scrollbar(res_frame, orient="vertical",
                             command=self._results.yview)
        self._results.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._results.pack(fill="both", expand=True)

        self._results.bind("<Double-1>", self._add_selected_to_table)

        ctx = tk.Menu(self, tearoff=0)
        ctx.add_command(label="Add to Address Table", command=self._add_selected_to_table)
        self._results.bind(
            "<Button-3>",
            lambda e: (self._results.selection_set(
                self._results.identify_row(e.y)),
                ctx.post(e.x_root, e.y_root)),
        )

    # ── Live value refresh ────────────────────────────────────────────────────

    def _schedule_live_refresh(self) -> None:
        if self._scanning or not self.app.pid or not self._scan_state:
            self.after(_LIVE_REFRESH_MS, self._schedule_live_refresh)
            return

        iids = list(self._results.get_children())
        if not iids:
            self.after(_LIVE_REFRESH_MS, self._schedule_live_refresh)
            return

        pid = self.app.pid
        dtype = self._scan_state.dtype
        item_size = 64 if is_variable_length(dtype) else type_size(dtype)

        def _bg():
            updates = []
            for iid in iids:
                try:
                    addr = int(iid, 16)
                    data = read_memory(pid, addr, item_size)
                    if data and len(data) == item_size:
                        val_str = format_value(dtype, unpack(dtype, data))
                    else:
                        val_str = "??"
                    updates.append((iid, val_str))
                except Exception:
                    pass
            self.after(0, lambda u=updates: self._apply_live_updates(u))

        threading.Thread(target=_bg, daemon=True).start()

    def _apply_live_updates(self, updates: list) -> None:
        for iid, val_str in updates:
            try:
                cur_vals = self._results.item(iid, "values")
                if cur_vals and len(cur_vals) >= 3 and cur_vals[2] != val_str:
                    self._results.item(iid, values=(cur_vals[0], cur_vals[1], val_str))
            except Exception:
                pass
        self.after(_LIVE_REFRESH_MS, self._schedule_live_refresh)

    # ── Mode/type helpers ─────────────────────────────────────────────────────

    def _on_type_change(self, _=None) -> None:
        pass

    def _on_mode_change(self, label: str) -> None:
        mode = self._label_to_mode(label)
        if mode == ScanMode.BETWEEN:
            self._to_label.pack(side="left", padx=4)
            self._val2_entry.pack(side="left")
        else:
            self._to_label.pack_forget()
            self._val2_entry.pack_forget()
        needs_val = mode not in (
            ScanMode.ANY, ScanMode.CHANGED, ScanMode.UNCHANGED,
            ScanMode.INCREASED, ScanMode.DECREASED,
        )
        self._val1_entry.configure(state="normal" if needs_val else "disabled")

    def _label_to_mode(self, label: str) -> ScanMode:
        for mode, lbl in _SCAN_MODE_LABELS.items():
            if lbl == label:
                return mode
        return ScanMode.EXACT

    def _current_dtype(self) -> DataType:
        label = self._type_var.get()
        for dt in ALL_TYPES:
            if display_name(dt) == label:
                return dt
        return DataType.INT32

    def _current_mode(self) -> ScanMode:
        return self._label_to_mode(self._mode_var.get())

    # ── Scan actions ──────────────────────────────────────────────────────────

    def _do_first_scan(self) -> None:
        if not self.app.pid:
            messagebox.showwarning("No Process", "Attach to a process first.", parent=self)
            return
        self._scan_state = None
        self._prev_scan_state = None
        self._results.delete(*self._results.get_children())
        self._do_scan(first=True)

    def _do_next_scan(self) -> None:
        if not self._scan_state:
            return
        # Save current state so Undo can restore it
        self._prev_scan_state = self._scan_state
        self._do_scan(first=False)

    def _undo_scan(self) -> None:
        if self._prev_scan_state is None:
            return
        self._scan_state = self._prev_scan_state
        self._prev_scan_state = None
        self._populate_results(self._scan_state)
        count = self._scan_state.count
        self._status.configure(
            text=f"Undone — {count:,} addresses (scan #{self._scan_state.scan_count})")
        self._progress.set(1.0)
        self._undo_btn.configure(state="disabled")
        self._finish_scan(success=True)

    def _do_new_scan(self) -> None:
        self._scan_state = None
        self._prev_scan_state = None
        self._results.delete(*self._results.get_children())
        self._status.configure(text="New scan ready.")
        self._progress.set(0)
        self._next_btn.configure(state="disabled")
        self._new_btn.configure(state="disabled")
        self._undo_btn.configure(state="disabled")
        self._add_all_btn.configure(state="disabled")
        self._mode_menu.configure(values=[_SCAN_MODE_LABELS[m] for m in _FIRST_SCAN_MODES])
        self._mode_var.set(_SCAN_MODE_LABELS[ScanMode.EXACT])
        self._val1_entry.configure(state="normal")
        self._first_btn.configure(state="normal")

    def _do_scan(self, first: bool = True) -> None:
        if self._scanning:
            return

        dtype = self._current_dtype()
        mode  = self._current_mode()
        val1_str = self._val1_var.get().strip()
        val2_str = self._val2_var.get().strip()

        # Validate: modes that require a value
        needs_val = mode not in (
            ScanMode.ANY, ScanMode.CHANGED, ScanMode.UNCHANGED,
            ScanMode.INCREASED, ScanMode.DECREASED,
        )
        if needs_val and not val1_str:
            messagebox.showwarning("Missing Value",
                                   "Enter a value to scan for.", parent=self)
            return

        try:
            val1 = self._parse_value(dtype, val1_str) if val1_str else None
            val2 = self._parse_value(dtype, val2_str) if val2_str else None
        except Exception as e:
            messagebox.showerror("Invalid value", str(e), parent=self)
            return

        self._scanning = True
        self._first_btn.configure(state="disabled")
        self._next_btn.configure(state="disabled")
        self._new_btn.configure(state="disabled")
        self._progress.set(0)
        self._status.configure(text="Scanning…")

        # Snapshot current scan state for the worker thread
        current_state = self._scan_state
        aligned = self._aligned_var.get()
        writable_only = self._writable_var.get()

        def progress_cb(done, total):
            if total > 0:
                self.after(0, lambda d=done, t=total: self._progress.set(d / t))

        def worker():
            try:
                if first or current_state is None:
                    result = first_scan(
                        self.app.pid, dtype, mode, val1, val2,
                        progress_callback=progress_cb,
                        aligned=aligned,
                        writable_only=writable_only,
                    )
                else:
                    result = next_scan(
                        current_state, mode, val1, val2,
                        progress_callback=progress_cb,
                    )
                self.after(0, lambda s=result: self._on_scan_done(s))
            except Exception as e:
                err = str(e)
                self.after(0, lambda: (
                    messagebox.showerror("Scan Error", err, parent=self),
                    self._finish_scan(success=False),
                ))

        threading.Thread(target=worker, daemon=True).start()

    def _parse_value(self, dtype: DataType, s: str):
        if dtype in (DataType.FLOAT32, DataType.FLOAT64):
            return float(s)
        if dtype == DataType.BOOL:
            return s.lower() in ("1", "true", "yes")
        if dtype in (DataType.STRING_ASCII, DataType.BYTE_ARRAY):
            return s
        return int(s, 0)

    def _on_scan_done(self, state: ScanState) -> None:
        self._scan_state = state
        self._populate_results(state)
        count = state.count
        cap = f" (capped at {MAX_RESULTS:,})" if count >= MAX_RESULTS else ""
        showing = min(count, _DISPLAY_LIMIT)
        self._status.configure(
            text=f"Found {count:,} addresses{cap} — showing {showing:,} — scan #{state.scan_count}")
        self._progress.set(1.0)
        self._finish_scan(success=True)

    def _finish_scan(self, success: bool = True) -> None:
        self._scanning = False
        if self._scan_state is not None:
            self._next_btn.configure(state="normal")
            self._new_btn.configure(state="normal")
            self._first_btn.configure(state="disabled")
            count = self._scan_state.count
            self._add_all_btn.configure(state="normal" if count > 0 else "disabled")
            self._undo_btn.configure(
                state="normal" if self._prev_scan_state is not None else "disabled")
            # Enable rescan modes
            self._mode_menu.configure(values=[_SCAN_MODE_LABELS[m] for m in _NEXT_SCAN_MODES])
        else:
            self._first_btn.configure(state="normal")
            self._next_btn.configure(state="disabled")
            self._undo_btn.configure(state="disabled")

    def _populate_results(self, state: ScanState) -> None:
        """
        Populate the results treeview. Shows live current values by reading
        from memory right now (not stale previous_bytes).
        """
        self._results.delete(*self._results.get_children())
        pid = self.app.pid
        dtype = state.dtype
        item_size = 64 if is_variable_length(dtype) else type_size(dtype)

        addr_fmt = getattr(self.app, "addr_fmt", "016X")
        resolver = make_module_resolver(pid) if pid else (lambda a: "")
        for entry in state.get_entries(_DISPLAY_LIMIT):
            # Read CURRENT value from memory (not stale previous_bytes)
            val_str = "??"
            data = read_memory(pid, entry.address, item_size) if pid else None
            if data and len(data) == item_size:
                try:
                    val_str = format_value(dtype, unpack(dtype, data))
                except Exception:
                    val_str = data[:item_size].hex()
            elif entry.previous_bytes:
                # Fallback to scan-time value if read fails
                try:
                    val_str = format_value(dtype, unpack(dtype, entry.previous_bytes))
                except Exception:
                    val_str = entry.previous_bytes.hex()

            module_str = resolver(entry.address)
            self._results.insert(
                "", "end",
                iid=hex(entry.address),
                values=(f"0x{entry.address:{addr_fmt}}", module_str, val_str),
            )

    # ── Add to table ──────────────────────────────────────────────────────────

    def _add_selected_to_table(self, event=None) -> None:
        if not self._scan_state:
            return
        sel = self._results.selection()
        if not sel:
            return
        for iid in sel:
            addr = int(iid, 16)
            entry = ScanEntry(address=addr, previous_bytes=b"")
            self.app.address_table.add_entry(entry, self._scan_state.dtype)

    def _add_all_to_table(self) -> None:
        if not self._scan_state:
            return
        MAX_ADD = 100
        entries = self._scan_state.get_entries(MAX_ADD)
        self.app.address_table.add_entries(entries, self._scan_state.dtype)
        self._status.configure(
            text=f"{self._status.cget('text')} — added {len(entries)} to table")
