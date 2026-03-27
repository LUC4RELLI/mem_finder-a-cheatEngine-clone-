"""
Process selection dialog.
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
        self.geometry("700x500")
        self.resizable(True, True)
        self.on_attach = on_attach
        self._all_procs: list[ProcessInfo] = []
        self._selected: Optional[ProcessInfo] = None

        self.transient(parent)
        self._build_ui()
        self._load_processes()
        self.after(100, self.grab_set)

    def _build_ui(self) -> None:
        # Search bar
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(10, 0))

        ctk.CTkLabel(top, text="Filter:").pack(side="left", padx=(0, 5))
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._apply_filter())
        ctk.CTkEntry(top, textvariable=self._search_var, width=250).pack(
            side="left", padx=(0, 10))

        ctk.CTkButton(top, text="Refresh", width=80,
                      command=self._load_processes).pack(side="left")

        # Treeview
        frame = ctk.CTkFrame(self)
        frame.pack(fill="both", expand=True, padx=10, pady=8)

        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview",
                         background="#2b2b2b", foreground="white",
                         rowheight=22, fieldbackground="#2b2b2b",
                         borderwidth=0)
        style.configure("Treeview.Heading",
                         background="#1f1f1f", foreground="white")
        style.map("Treeview", background=[("selected", "#1f538d")])

        cols = ("pid", "name", "arch", "user")
        self._tree = ttk.Treeview(frame, columns=cols, show="headings",
                                   selectmode="browse")
        for col, label, width in [
            ("pid",  "PID",   70),
            ("name", "Name",  260),
            ("arch", "Arch",  60),
            ("user", "User",  180),
        ]:
            self._tree.heading(col, text=label,
                               command=lambda c=col: self._sort(c))
            self._tree.column(col, width=width, anchor="w")

        vsb = ttk.Scrollbar(frame, orient="vertical",
                             command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True)
        self._tree.bind("<Double-1>", lambda _: self._do_attach())

        # Bottom bar
        bottom = ctk.CTkFrame(self, fg_color="transparent")
        bottom.pack(fill="x", padx=10, pady=(0, 10))

        self._status = ctk.CTkLabel(bottom, text="Loading…")
        self._status.pack(side="left")
        ctk.CTkButton(bottom, text="Cancel", width=80,
                      command=self.destroy).pack(side="right", padx=(5, 0))
        ctk.CTkButton(bottom, text="Attach", width=80,
                      command=self._do_attach).pack(side="right")

        self._sort_col = "name"
        self._sort_rev = False

    def _load_processes(self) -> None:
        self._status.configure(text="Refreshing…")

        def worker():
            procs = list_processes()
            self.after(0, lambda: self._populate(procs))

        threading.Thread(target=worker, daemon=True).start()

    def _populate(self, procs: list[ProcessInfo]) -> None:
        self._all_procs = procs
        self._apply_filter()
        self._status.configure(text=f"{len(procs)} processes")

    def _apply_filter(self) -> None:
        q = self._search_var.get().lower()
        self._tree.delete(*self._tree.get_children())
        for p in self._all_procs:
            if q and q not in p.name.lower() and q not in str(p.pid):
                continue
            self._tree.insert("", "end", iid=str(p.pid),
                              values=(p.pid, p.name,
                                      f"{p.arch}-bit", p.username))

    def _sort(self, col: str) -> None:
        if self._sort_col == col:
            self._sort_rev = not self._sort_rev
        else:
            self._sort_col = col
            self._sort_rev = False

        key_map = {
            "pid": lambda p: p.pid,
            "name": lambda p: p.name.lower(),
            "arch": lambda p: p.arch,
            "user": lambda p: p.username.lower(),
        }
        self._all_procs.sort(key=key_map[col], reverse=self._sort_rev)
        self._apply_filter()

    def _do_attach(self) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        pid = int(sel[0])
        proc = next((p for p in self._all_procs if p.pid == pid), None)
        if proc:
            self.destroy()
            self.on_attach(proc)
