"""
Watchpoint management frame.
"""
from __future__ import annotations
import time
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Optional

import customtkinter as ctk

from core.watchpoint import WatchpointManager, WatchpointHit


class WatchpointFrame(ctk.CTkFrame):
    def __init__(self, parent, app, **kwargs):
        super().__init__(parent, **kwargs)
        self.app = app
        self._manager: Optional[WatchpointManager] = None
        self._hits: list[WatchpointHit] = []
        self._build_ui()

    def _build_ui(self) -> None:
        # Add watchpoint controls
        add_frame = ctk.CTkFrame(self)
        add_frame.pack(fill="x", padx=8, pady=(8, 4))

        ctk.CTkLabel(add_frame, text="Add Watchpoint",
                     font=ctk.CTkFont(size=13, weight="bold")).pack(
            anchor="w", pady=(4, 6))

        row = ctk.CTkFrame(add_frame, fg_color="transparent")
        row.pack(fill="x")

        ctk.CTkLabel(row, text="Address:").pack(side="left", padx=(0, 4))
        self._addr_var = tk.StringVar()
        ctk.CTkEntry(row, textvariable=self._addr_var, width=160).pack(
            side="left", padx=(0, 8))

        ctk.CTkLabel(row, text="Type:").pack(side="left", padx=(0, 4))
        self._type_var = tk.StringVar(value="Read/Write")
        ctk.CTkOptionMenu(
            row, variable=self._type_var,
            values=["Read/Write", "Write Only", "Execute"],
            width=130,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkLabel(row, text="Size:").pack(side="left", padx=(0, 4))
        self._size_var = tk.StringVar(value="4")
        ctk.CTkOptionMenu(
            row, variable=self._size_var,
            values=["1", "2", "4", "8"],
            width=70,
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(row, text="Add", width=70,
                      command=self._add_watchpoint).pack(side="left")

        # Note about requirements
        note = ctk.CTkLabel(
            add_frame,
            text="Note: Watchpoints require ptrace access. Run with sudo or set ptrace_scope=0.",
            font=ctk.CTkFont(size=10),
            text_color="#888888",
        )
        note.pack(anchor="w", pady=(4, 0))

        # Active watchpoints table
        wp_frame = ctk.CTkFrame(self)
        wp_frame.pack(fill="x", padx=8, pady=4)

        ctk.CTkLabel(wp_frame, text="Active Watchpoints",
                     font=ctk.CTkFont(size=12, weight="bold")).pack(
            anchor="w", pady=(4, 4))

        style = ttk.Style()
        style.theme_use("default")
        style.configure("WP.Treeview",
                         background="#1e1e1e", foreground="white",
                         rowheight=20, fieldbackground="#1e1e1e",
                         borderwidth=0)
        style.configure("WP.Treeview.Heading",
                         background="#2a2a2a", foreground="#aaaaaa")
        style.map("WP.Treeview",
                  background=[("selected", "#1f538d")])

        cols = ("slot", "address", "type", "size", "hits")
        self._wp_tree = ttk.Treeview(wp_frame, columns=cols,
                                      show="headings", style="WP.Treeview",
                                      height=4)
        for col, label, width in [
            ("slot",    "#",      40),
            ("address", "Address", 160),
            ("type",    "Type",    100),
            ("size",    "Size",     50),
            ("hits",    "Hits",     50),
        ]:
            self._wp_tree.heading(col, text=label)
            self._wp_tree.column(col, width=width, anchor="w")
        self._wp_tree.pack(fill="x")

        btn_row = ctk.CTkFrame(wp_frame, fg_color="transparent")
        btn_row.pack(fill="x", pady=(4, 0))
        ctk.CTkButton(btn_row, text="Remove Selected", width=140,
                      command=self._remove_selected).pack(side="left")
        ctk.CTkButton(btn_row, text="Remove All", width=100,
                      fg_color="#553333",
                      command=self._remove_all).pack(side="left", padx=(8, 0))

        # Hit log
        log_frame = ctk.CTkFrame(self)
        log_frame.pack(fill="both", expand=True, padx=8, pady=(4, 8))

        log_header = ctk.CTkFrame(log_frame, fg_color="transparent")
        log_header.pack(fill="x")
        ctk.CTkLabel(log_header, text="Access Log",
                     font=ctk.CTkFont(size=12, weight="bold")).pack(side="left")
        ctk.CTkButton(log_header, text="Clear Log", width=90,
                      command=self._clear_log).pack(side="right")

        style.configure("Log.Treeview",
                         background="#1a1a1a", foreground="#cccccc",
                         rowheight=20, fieldbackground="#1a1a1a",
                         borderwidth=0)
        style.configure("Log.Treeview.Heading",
                         background="#222222", foreground="#888888")
        style.map("Log.Treeview", background=[("selected", "#1f538d")])

        log_cols = ("time", "wp_addr", "caller_ip", "instruction", "tid")
        self._log_tree = ttk.Treeview(log_frame, columns=log_cols,
                                       show="headings", style="Log.Treeview")
        for col, label, width in [
            ("time",        "Time",         80),
            ("wp_addr",     "WP Address",  140),
            ("caller_ip",   "Caller IP",   140),
            ("instruction", "Instruction", 260),
            ("tid",         "TID",          60),
        ]:
            self._log_tree.heading(col, text=label)
            self._log_tree.column(col, width=width, anchor="w")

        log_vsb = ttk.Scrollbar(log_frame, orient="vertical",
                                  command=self._log_tree.yview)
        self._log_tree.configure(yscrollcommand=log_vsb.set)
        log_vsb.pack(side="right", fill="y")
        self._log_tree.pack(fill="both", expand=True, pady=(4, 0))

        # Double-click log entry to go to caller address in memory view
        self._log_tree.bind("<Double-1>", self._on_log_double_click)

        self._hit_counts: dict[int, int] = {}  # wp_addr -> count

    # ── Watchpoint management ─────────────────────────────────────────────────

    def _ensure_manager(self) -> bool:
        if not self.app.pid:
            messagebox.showwarning("No Process",
                                   "Attach to a process first.", parent=self)
            return False
        if self._manager is None or self._manager.pid != self.app.pid:
            if self._manager:
                self._manager.stop()
            self._manager = WatchpointManager(
                self.app.pid,
                hit_callback=self._on_hit,
            )
        return True

    def add_watchpoint_for_address(self, addr: int) -> None:
        """Called from address table context menu."""
        self._addr_var.set(f"0x{addr:X}")
        if self._ensure_manager():
            self._add_watchpoint()

    def _add_watchpoint(self) -> None:
        if not self._ensure_manager():
            return
        s = self._addr_var.get().strip()
        try:
            addr = int(s, 0)
        except ValueError:
            messagebox.showerror("Invalid address", f"Cannot parse: {s!r}",
                                  parent=self)
            return

        type_map = {"Read/Write": "rw", "Write Only": "write", "Execute": "exec"}
        wtype = type_map[self._type_var.get()]
        size  = int(self._size_var.get())

        try:
            ok = self._manager.add_watchpoint(addr, wtype, size)
            if not ok:
                messagebox.showwarning(
                    "No Slots",
                    "Maximum 4 hardware watchpoints already active.",
                    parent=self,
                )
                return
            self._manager.start()
            self._refresh_wp_table()
        except Exception as e:
            messagebox.showerror("Error", str(e), parent=self)

    def _remove_selected(self) -> None:
        sel = self._wp_tree.selection()
        if not sel or not self._manager:
            return
        for iid in sel:
            addr = int(self._wp_tree.item(iid)["values"][1], 16)
            self._manager.remove_watchpoint(addr)
        self._refresh_wp_table()

    def _remove_all(self) -> None:
        if not self._manager:
            return
        for _, addr, _, _ in list(self._manager.list_watchpoints()):
            self._manager.remove_watchpoint(addr)
        if self._manager.slot_count == 0:
            self._manager.stop()
        self._refresh_wp_table()

    def _refresh_wp_table(self) -> None:
        self._wp_tree.delete(*self._wp_tree.get_children())
        if not self._manager:
            return
        for slot, addr, wtype, size in self._manager.list_watchpoints():
            hits = self._hit_counts.get(addr, 0)
            self._wp_tree.insert("", "end",
                iid=f"wp_{slot}",
                values=(slot, f"0x{addr:016X}", wtype, size, hits),
            )

    def _on_hit(self, hit: WatchpointHit) -> None:
        """Called from watchpoint thread; must use after() to update GUI."""
        self._hits.append(hit)
        self._hit_counts[hit.watchpoint_addr] = (
            self._hit_counts.get(hit.watchpoint_addr, 0) + 1)
        self.after(0, self._append_hit_to_log, hit)
        self.after(0, self._refresh_wp_table)

    def _append_hit_to_log(self, hit: WatchpointHit) -> None:
        ts = time.strftime("%H:%M:%S", time.localtime(hit.timestamp))
        ms = int((hit.timestamp % 1) * 1000)
        self._log_tree.insert(
            "", "end",
            values=(
                f"{ts}.{ms:03d}",
                f"0x{hit.watchpoint_addr:X}",
                f"0x{hit.caller_ip:X}",
                hit.instruction,
                hit.thread_id,
            ),
        )
        # Auto-scroll to newest
        children = self._log_tree.get_children()
        if children:
            self._log_tree.see(children[-1])

    def _clear_log(self) -> None:
        self._log_tree.delete(*self._log_tree.get_children())
        self._hits.clear()
        self._hit_counts.clear()
        self._refresh_wp_table()

    def _on_log_double_click(self, event) -> None:
        sel = self._log_tree.selection()
        if not sel:
            return
        vals = self._log_tree.item(sel[0])["values"]
        try:
            caller_ip = int(str(vals[2]), 16)
            self.app.open_memory_view_at(caller_ip)
        except Exception:
            pass

    def on_process_changed(self) -> None:
        """Reset when process changes."""
        if self._manager:
            self._manager.stop()
            self._manager = None
        self._wp_tree.delete(*self._wp_tree.get_children())
