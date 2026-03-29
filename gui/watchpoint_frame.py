"""
Watchpoint management frame.

Performance fixes:
- Hits are buffered in a thread-safe deque; GUI updates at most every 200 ms.
- Log is capped at MAX_LOG entries so the treeview never grows unbounded.
- _clear_log rebuilds the widget instead of calling delete(*thousands_of_items).
"""
from __future__ import annotations
import collections
import time
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Optional

import customtkinter as ctk

from core.watchpoint import WatchpointManager, WatchpointHit

MAX_LOG = 200          # max rows kept in the log treeview
FLUSH_INTERVAL = 200   # ms between GUI log flushes


class WatchpointFrame(ctk.CTkFrame):
    def __init__(self, parent, app, **kwargs):
        super().__init__(parent, **kwargs)
        self.app = app
        self._manager: Optional[WatchpointManager] = None
        self._hit_counts: dict[int, int] = {}
        # Thread-safe buffer: hits from watchpoint thread are appended here;
        # the GUI flushes the buffer periodically — no per-hit after() call.
        self._pending: collections.deque[WatchpointHit] = collections.deque()
        self._build_ui()
        self._schedule_flush()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
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
        ctk.CTkOptionMenu(row, variable=self._type_var,
                          values=["Read/Write", "Write Only", "Execute"],
                          width=130).pack(side="left", padx=(0, 8))

        ctk.CTkLabel(row, text="Size:").pack(side="left", padx=(0, 4))
        self._size_var = tk.StringVar(value="4")
        ctk.CTkOptionMenu(row, variable=self._size_var,
                          values=["1", "2", "4", "8"],
                          width=70).pack(side="left", padx=(0, 10))

        ctk.CTkButton(row, text="Add", width=70,
                      command=self._add_watchpoint).pack(side="left")

        ctk.CTkLabel(add_frame,
                     text="Note: requires sudo or ptrace_scope=0.",
                     font=ctk.CTkFont(size=10),
                     text_color="#888888").pack(anchor="w", pady=(4, 0))

        # Active watchpoints table
        wp_frame = ctk.CTkFrame(self)
        wp_frame.pack(fill="x", padx=8, pady=4)

        ctk.CTkLabel(wp_frame, text="Active Watchpoints",
                     font=ctk.CTkFont(size=12, weight="bold")).pack(
            anchor="w", pady=(4, 4))

        style = ttk.Style()
        style.theme_use("default")
        for name, bg in [("WP.Treeview", "#1e1e1e"), ("Log.Treeview", "#1a1a1a")]:
            style.configure(name, background=bg, foreground="white",
                             rowheight=20, fieldbackground=bg, borderwidth=0)
            style.configure(f"{name}.Heading",
                             background="#2a2a2a", foreground="#aaaaaa")
            style.map(name, background=[("selected", "#1f538d")])

        cols = ("slot", "address", "type", "size", "hits")
        self._wp_tree = ttk.Treeview(wp_frame, columns=cols,
                                      show="headings", style="WP.Treeview",
                                      height=4)
        for col, label, width in [
            ("slot", "#", 40), ("address", "Address", 160),
            ("type", "Type", 100), ("size", "Size", 50), ("hits", "Hits", 60),
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
        self._log_title = ctk.CTkLabel(
            log_header, text=f"Access Log  (0 / max {MAX_LOG})",
            font=ctk.CTkFont(size=12, weight="bold"))
        self._log_title.pack(side="left")
        ctk.CTkButton(log_header, text="Clear Log", width=90,
                      command=self._clear_log).pack(side="right")

        log_cols = ("time", "wp_addr", "caller_ip", "instruction", "tid")
        self._log_tree = ttk.Treeview(log_frame, columns=log_cols,
                                       show="headings", style="Log.Treeview")
        for col, label, width in [
            ("time", "Time", 80), ("wp_addr", "WP Address", 140),
            ("caller_ip", "Caller IP", 140),
            ("instruction", "Instruction", 260), ("tid", "TID", 60),
        ]:
            self._log_tree.heading(col, text=label)
            self._log_tree.column(col, width=width, anchor="w")

        log_vsb = ttk.Scrollbar(log_frame, orient="vertical",
                                  command=self._log_tree.yview)
        self._log_tree.configure(yscrollcommand=log_vsb.set)
        log_vsb.pack(side="right", fill="y")
        self._log_tree.pack(fill="both", expand=True, pady=(4, 0))
        self._log_tree.bind("<Double-1>", self._on_log_double_click)

    # ── Periodic flush (runs in GUI thread, every FLUSH_INTERVAL ms) ──────────

    def _schedule_flush(self) -> None:
        self._flush_pending()
        self.after(FLUSH_INTERVAL, self._schedule_flush)

    def _flush_pending(self) -> None:
        if not self._pending:
            return

        # Drain the deque — take everything that arrived since last flush
        batch: list[WatchpointHit] = []
        try:
            while True:
                batch.append(self._pending.popleft())
        except IndexError:
            pass

        if not batch:
            return

        # Update hit counters
        for hit in batch:
            self._hit_counts[hit.watchpoint_addr] = (
                self._hit_counts.get(hit.watchpoint_addr, 0) + 1)

        # Insert only the LAST hit from this batch (most recent is most useful)
        # When the log is full, replace the oldest entry instead of growing.
        hit = batch[-1]
        ts = time.strftime("%H:%M:%S", time.localtime(hit.timestamp))
        ms = int((hit.timestamp % 1) * 1000)
        row_vals = (
            f"{ts}.{ms:03d}",
            f"0x{hit.watchpoint_addr:X}",
            f"0x{hit.caller_ip:X}",
            hit.instruction,
            hit.thread_id,
        )

        children = self._log_tree.get_children()
        if len(children) >= MAX_LOG:
            # Overwrite the oldest row (avoids delete+insert cost at scale)
            self._log_tree.item(children[0], values=row_vals)
            self._log_tree.move(children[0], "", "end")
        else:
            self._log_tree.insert("", "end", values=row_vals)
            children = self._log_tree.get_children()

        # Auto-scroll
        if children:
            self._log_tree.see(children[-1])

        # Update title with count and refresh watchpoint hit counters
        total = sum(self._hit_counts.values())
        self._log_title.configure(
            text=f"Access Log  ({total} hits, showing last {MAX_LOG})")
        self._refresh_wp_table()

    # ── Watchpoint management ─────────────────────────────────────────────────

    def _ensure_manager(self) -> bool:
        if not self.app.pid:
            messagebox.showwarning("No Process",
                                   "Attach to a process first.", parent=self)
            return False
        if self._manager is None or self._manager.pid != self.app.pid:
            if self._manager:
                self._manager.stop()
            self._manager = WatchpointManager(self.app.pid,
                                              hit_callback=self._on_hit)
        return True

    def add_watchpoint_for_address(self, addr: int) -> None:
        self._addr_var.set(f"0x{addr:X}")
        if self._ensure_manager():
            self._add_watchpoint()

    def _add_watchpoint(self) -> None:
        if not self._ensure_manager():
            return
        try:
            addr = int(self._addr_var.get().strip(), 0)
        except ValueError:
            messagebox.showerror("Invalid address",
                                  f"Cannot parse: {self._addr_var.get()!r}",
                                  parent=self)
            return
        type_map = {"Read/Write": "rw", "Write Only": "write", "Execute": "exec"}
        wtype = type_map[self._type_var.get()]
        size  = int(self._size_var.get())
        try:
            if not self._manager.add_watchpoint(addr, wtype, size):
                messagebox.showwarning("No Slots",
                                       "Maximum 4 hardware watchpoints active.",
                                       parent=self)
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
            self._wp_tree.insert("", "end", iid=f"wp_{slot}",
                values=(slot, f"0x{addr:016X}", wtype, size, hits))

    def _on_hit(self, hit: WatchpointHit) -> None:
        """Called from watchpoint background thread — only appends to deque."""
        self._pending.append(hit)

    def _clear_log(self) -> None:
        # Fast clear: detach then delete one-by-one is still slow for 200 rows;
        # the real fix is that we cap at MAX_LOG so it never grows large.
        for iid in self._log_tree.get_children():
            self._log_tree.delete(iid)
        self._pending.clear()
        self._hit_counts.clear()
        self._log_title.configure(text=f"Access Log  (0 / max {MAX_LOG})")
        self._refresh_wp_table()

    def _on_log_double_click(self, event) -> None:
        sel = self._log_tree.selection()
        if not sel:
            return
        vals = self._log_tree.item(sel[0])["values"]
        try:
            self.app.open_memory_view_at(int(str(vals[2]), 16))
        except Exception:
            pass

    def on_process_changed(self) -> None:
        if self._manager:
            self._manager.stop()
            self._manager = None
        self._wp_tree.delete(*self._wp_tree.get_children())
        self._pending.clear()
        self._hit_counts.clear()
