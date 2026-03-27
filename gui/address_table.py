"""
Address table frame: displays scan results with live values, freeze, and edit.
"""
from __future__ import annotations
import threading
import time
import tkinter as tk
from tkinter import ttk, simpledialog
from typing import Callable, Optional

import customtkinter as ctk

from core.data_types import DataType, format_value, pack, unpack, type_size, is_variable_length
from core.memory_io import read_memory, write_memory
from core.memory_scanner import ScanEntry


class AddressRow:
    def __init__(self, entry: ScanEntry, dtype: DataType, description: str = ""):
        self.address = entry.address
        self.dtype = dtype
        self.description = description
        self.frozen = False
        self.freeze_value: Optional[bytes] = None
        self._freeze_thread: Optional[threading.Thread] = None
        self._freeze_stop = threading.Event()

    def start_freeze(self, value_bytes: bytes) -> None:
        self.frozen = True
        self.freeze_value = value_bytes
        self._freeze_stop.clear()

        def writer():
            import os
            pid = self._pid
            while not self._freeze_stop.is_set():
                write_memory(pid, self.address, value_bytes)
                time.sleep(0.1)

        self._freeze_thread = threading.Thread(target=writer, daemon=True)
        self._freeze_thread.start()

    def stop_freeze(self) -> None:
        self.frozen = False
        self._freeze_stop.set()

    def set_pid(self, pid: int) -> None:
        self._pid = pid


class AddressTableFrame(ctk.CTkFrame):
    """
    Scrollable table showing tracked addresses with:
    - Live value refresh (every 500ms)
    - Freeze toggle
    - Inline value editing
    - Context menu: watch accesses, view in memory view
    """

    def __init__(self, parent, app, **kwargs):
        super().__init__(parent, **kwargs)
        self.app = app
        self._rows: list[AddressRow] = []
        self._refresh_after_id = None
        self._build_ui()
        self._schedule_refresh()

    def _build_ui(self) -> None:
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=5, pady=(5, 2))

        ctk.CTkLabel(top, text="Address Table",
                     font=ctk.CTkFont(size=13, weight="bold")).pack(side="left")
        ctk.CTkButton(top, text="Clear All", width=80,
                      command=self.clear_all).pack(side="right")

        style = ttk.Style()
        style.theme_use("default")
        style.configure("Addr.Treeview",
                         background="#1e1e1e", foreground="white",
                         rowheight=22, fieldbackground="#1e1e1e",
                         borderwidth=0)
        style.configure("Addr.Treeview.Heading",
                         background="#2a2a2a", foreground="#aaaaaa")
        style.map("Addr.Treeview",
                  background=[("selected", "#1f538d")])

        frame = ctk.CTkFrame(self)
        frame.pack(fill="both", expand=True, padx=5, pady=(0, 5))

        cols = ("address", "type", "value", "frozen", "description")
        self._tree = ttk.Treeview(frame, columns=cols,
                                   show="headings", style="Addr.Treeview",
                                   selectmode="extended")
        for col, label, width in [
            ("address",     "Address",     140),
            ("type",        "Type",         90),
            ("value",       "Value",        120),
            ("frozen",      "Frozen",        60),
            ("description", "Description",  180),
        ]:
            self._tree.heading(col, text=label)
            self._tree.column(col, width=width, anchor="w")

        vsb = ttk.Scrollbar(frame, orient="vertical",
                             command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True)

        self._tree.bind("<Double-1>", self._on_double_click)
        self._tree.bind("<Button-3>", self._on_right_click)
        self._tree.bind("<Delete>", lambda _: self._remove_selected())

        # Context menu
        self._ctx = tk.Menu(self, tearoff=0)
        self._ctx.add_command(label="Edit Value",
                              command=self._edit_selected)
        self._ctx.add_command(label="Toggle Freeze",
                              command=self._toggle_freeze_selected)
        self._ctx.add_separator()
        self._ctx.add_command(label="Find what accesses this",
                              command=self._watch_selected)
        self._ctx.add_command(label="View in Memory View",
                              command=self._view_memory_selected)
        self._ctx.add_separator()
        self._ctx.add_command(label="Remove",
                              command=self._remove_selected)

    def add_entry(self, entry: ScanEntry, dtype: DataType,
                   description: str = "") -> None:
        # Don't add duplicates
        if any(r.address == entry.address for r in self._rows):
            return
        row = AddressRow(entry, dtype, description)
        if self.app.pid:
            row.set_pid(self.app.pid)
        self._rows.append(row)
        self._refresh_row(row)

    def add_entries(self, entries: list[ScanEntry], dtype: DataType) -> None:
        for e in entries:
            self.add_entry(e, dtype)

    def clear_all(self) -> None:
        for row in self._rows:
            row.stop_freeze()
        self._rows.clear()
        self._tree.delete(*self._tree.get_children())

    def _refresh_row(self, row: AddressRow) -> None:
        iid = hex(row.address)
        pid = self.app.pid
        value_str = "—"
        if pid:
            size = 64 if is_variable_length(row.dtype) else type_size(row.dtype)
            data = read_memory(pid, row.address, size)
            if data:
                try:
                    val = unpack(row.dtype, data)
                    value_str = format_value(row.dtype, val)
                except Exception:
                    value_str = data.hex()

        frozen_str = "✓" if row.frozen else ""
        vals = (
            f"0x{row.address:016X}",
            row.dtype.name,
            value_str,
            frozen_str,
            row.description,
        )
        if self._tree.exists(iid):
            self._tree.item(iid, values=vals)
        else:
            self._tree.insert("", "end", iid=iid, values=vals)
            if row.frozen:
                self._tree.item(iid, tags=("frozen",))
        self._tree.tag_configure("frozen", foreground="#44aaff")

    def _schedule_refresh(self) -> None:
        self._do_refresh()
        self._refresh_after_id = self.after(500, self._schedule_refresh)

    def _do_refresh(self) -> None:
        if not self.app.pid:
            return
        for row in self._rows:
            try:
                self._refresh_row(row)
            except Exception:
                pass

    def _selected_row(self) -> Optional[AddressRow]:
        sel = self._tree.selection()
        if not sel:
            return None
        addr = int(sel[0], 16)
        return next((r for r in self._rows if r.address == addr), None)

    def _on_double_click(self, event) -> None:
        self._edit_selected()

    def _on_right_click(self, event) -> None:
        item = self._tree.identify_row(event.y)
        if item:
            self._tree.selection_set(item)
        self._ctx.post(event.x_root, event.y_root)

    def _edit_selected(self) -> None:
        row = self._selected_row()
        if not row or not self.app.pid:
            return
        current = ""
        size = 64 if is_variable_length(row.dtype) else type_size(row.dtype)
        data = read_memory(self.app.pid, row.address, size)
        if data:
            try:
                current = format_value(row.dtype, unpack(row.dtype, data))
            except Exception:
                current = data.hex()

        new_val = simpledialog.askstring(
            "Edit Value",
            f"Address: 0x{row.address:X}\nType: {row.dtype.name}\n\nNew value:",
            initialvalue=current,
            parent=self,
        )
        if new_val is None:
            return
        try:
            raw = pack(row.dtype, new_val)
            write_memory(self.app.pid, row.address, raw)
            if row.frozen:
                row.freeze_value = raw
        except Exception as e:
            from tkinter import messagebox
            messagebox.showerror("Error", str(e), parent=self)

    def _toggle_freeze_selected(self) -> None:
        row = self._selected_row()
        if not row or not self.app.pid:
            return
        if row.frozen:
            row.stop_freeze()
        else:
            size = 64 if is_variable_length(row.dtype) else type_size(row.dtype)
            data = read_memory(self.app.pid, row.address, size)
            if data:
                row.set_pid(self.app.pid)
                row.start_freeze(data)
        self._refresh_row(row)

    def _remove_selected(self) -> None:
        sel = self._tree.selection()
        for iid in sel:
            addr = int(iid, 16)
            row = next((r for r in self._rows if r.address == addr), None)
            if row:
                row.stop_freeze()
                self._rows.remove(row)
            self._tree.delete(iid)

    def _watch_selected(self) -> None:
        row = self._selected_row()
        if row:
            self.app.open_watchpoint_for(row.address)

    def _view_memory_selected(self) -> None:
        row = self._selected_row()
        if row:
            self.app.open_memory_view_at(row.address)
