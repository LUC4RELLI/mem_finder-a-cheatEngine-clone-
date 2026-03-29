"""
Process selection dialog — grouped by name, debounced search.
"""
from __future__ import annotations
import threading
import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional

import customtkinter as ctk

from core.process_manager import ProcessInfo, list_processes


class ProcessDialog(ctk.CTkToplevel):
    def __init__(self, parent, on_attach: Callable[[ProcessInfo], None]):
        super().__init__(parent)
        self.title("Select Process")
        self.geometry("700x520")
        self.resizable(True, True)
        self.on_attach = on_attach
        # name -> list[ProcessInfo]
        self._groups: dict[str, list[ProcessInfo]] = {}
        self._debounce_id = None

        self.transient(parent)
        self._build_ui()
        self._load_processes()
        self.after(100, self.grab_set)

    def _build_ui(self) -> None:
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(10, 0))

        ctk.CTkLabel(top, text="Filter:").pack(side="left", padx=(0, 5))
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._schedule_filter())
        ctk.CTkEntry(top, textvariable=self._search_var, width=250).pack(
            side="left", padx=(0, 10))
        ctk.CTkButton(top, text="Refresh", width=80,
                      command=self._load_processes).pack(side="left")

        # Treeview
        frame = ctk.CTkFrame(self)
        frame.pack(fill="both", expand=True, padx=10, pady=8)

        style = ttk.Style()
        style.theme_use("default")
        style.configure("PD.Treeview",
                         background="#2b2b2b", foreground="white",
                         rowheight=22, fieldbackground="#2b2b2b", borderwidth=0)
        style.configure("PD.Treeview.Heading",
                         background="#1f1f1f", foreground="white")
        style.map("PD.Treeview", background=[("selected", "#1f538d")])

        cols = ("name", "pid", "arch", "user")
        self._tree = ttk.Treeview(frame, columns=cols, show="tree headings",
                                   style="PD.Treeview", selectmode="browse")
        self._tree.heading("#0",   text="")
        self._tree.heading("name", text="Name")
        self._tree.heading("pid",  text="PID")
        self._tree.heading("arch", text="Arch")
        self._tree.heading("user", text="User")
        self._tree.column("#0",   width=20,  stretch=False)
        self._tree.column("name", width=260, anchor="w")
        self._tree.column("pid",  width=70,  anchor="w")
        self._tree.column("arch", width=60,  anchor="w")
        self._tree.column("user", width=160, anchor="w")

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True)

        self._tree.bind("<Double-1>", lambda _: self._do_attach())

        bottom = ctk.CTkFrame(self, fg_color="transparent")
        bottom.pack(fill="x", padx=10, pady=(0, 10))
        self._status = ctk.CTkLabel(bottom, text="Loading…")
        self._status.pack(side="left")
        ctk.CTkButton(bottom, text="Cancel", width=80,
                      command=self.destroy).pack(side="right", padx=(5, 0))
        ctk.CTkButton(bottom, text="Attach", width=80,
                      command=self._do_attach).pack(side="right")

    # ── Data loading ──────────────────────────────────────────────────────────

    def _load_processes(self) -> None:
        self._status.configure(text="Refreshing…")
        threading.Thread(target=self._fetch_worker, daemon=True).start()

    def _fetch_worker(self) -> None:
        procs = list_processes()
        groups: dict[str, list[ProcessInfo]] = {}
        for p in procs:
            groups.setdefault(p.name, []).append(p)
        self.after(0, lambda: self._on_loaded(groups))

    def _on_loaded(self, groups: dict[str, list[ProcessInfo]]) -> None:
        self._groups = groups
        total = sum(len(v) for v in groups.values())
        self._status.configure(
            text=f"{total} processes, {len(groups)} unique names")
        self._apply_filter()

    # ── Filtering ─────────────────────────────────────────────────────────────

    def _schedule_filter(self) -> None:
        """Debounce: wait 150 ms after last keystroke before re-rendering."""
        if self._debounce_id:
            self.after_cancel(self._debounce_id)
        self._debounce_id = self.after(150, self._apply_filter)

    def _apply_filter(self) -> None:
        q = self._search_var.get().lower().strip()
        self._tree.delete(*self._tree.get_children())

        for name, procs in sorted(self._groups.items(),
                                   key=lambda kv: kv[0].lower()):
            # Filter: any proc in group must match query
            if q:
                if not any(
                    q in p.name.lower()
                    or q in str(p.pid)
                    or q in p.username.lower()
                    for p in procs
                ):
                    continue

            count = len(procs)
            if count == 1:
                p = procs[0]
                self._tree.insert(
                    "", "end", iid=f"pid_{p.pid}",
                    values=(p.name, p.pid, f"{p.arch}-bit", p.username),
                )
            else:
                # Group parent row
                group_iid = f"grp_{name}"
                label = f"({count})  {name}"
                first = procs[0]
                self._tree.insert(
                    "", "end", iid=group_iid,
                    values=(label, "—", f"{first.arch}-bit", first.username),
                    open=False,
                )
                # Child rows
                for p in sorted(procs, key=lambda x: x.pid):
                    self._tree.insert(
                        group_iid, "end", iid=f"pid_{p.pid}",
                        values=(f"  {p.name}", p.pid,
                                f"{p.arch}-bit", p.username),
                    )

    # ── Attach ────────────────────────────────────────────────────────────────

    def _do_attach(self) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        iid = sel[0]

        if iid.startswith("grp_"):
            # Expand group so user can pick a specific PID
            self._tree.item(iid, open=True)
            return

        # iid is "pid_1234"
        pid = int(iid.split("_", 1)[1])
        proc = next(
            (p for plist in self._groups.values()
             for p in plist if p.pid == pid),
            None,
        )
        if proc:
            self.destroy()
            self.on_attach(proc)
