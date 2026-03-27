"""
Pointer scanner frame.
"""
from __future__ import annotations
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Optional

import customtkinter as ctk

from core.pointer_scanner import PointerScanner, PointerChain
from core.memory_scanner import ScanEntry
from core.data_types import DataType


class PointerFrame(ctk.CTkFrame):
    def __init__(self, parent, app, **kwargs):
        super().__init__(parent, **kwargs)
        self.app = app
        self._scanner: Optional[PointerScanner] = None
        self._chains: list[PointerChain] = []
        self._scanning = False
        self._build_ui()

    def _build_ui(self) -> None:
        # Controls
        ctrl = ctk.CTkFrame(self)
        ctrl.pack(fill="x", padx=8, pady=(8, 4))

        ctk.CTkLabel(ctrl, text="Pointer Scanner",
                     font=ctk.CTkFont(size=13, weight="bold")).pack(
            anchor="w", pady=(4, 6))

        row1 = ctk.CTkFrame(ctrl, fg_color="transparent")
        row1.pack(fill="x")

        ctk.CTkLabel(row1, text="Target Address:").pack(side="left", padx=(0, 4))
        self._addr_var = tk.StringVar()
        ctk.CTkEntry(row1, textvariable=self._addr_var, width=170).pack(
            side="left", padx=(0, 12))

        ctk.CTkLabel(row1, text="Max Depth:").pack(side="left", padx=(0, 4))
        self._depth_var = tk.StringVar(value="4")
        ctk.CTkOptionMenu(row1, variable=self._depth_var,
                          values=["2", "3", "4", "5", "6"],
                          width=70).pack(side="left", padx=(0, 12))

        ctk.CTkLabel(row1, text="Search Range:").pack(side="left", padx=(0, 4))
        self._range_var = tk.StringVar(value="0x500")
        ctk.CTkEntry(row1, textvariable=self._range_var, width=90).pack(
            side="left", padx=(0, 12))

        ctk.CTkLabel(row1, text="Arch:").pack(side="left", padx=(0, 4))
        self._arch_var = tk.StringVar(value="64-bit")
        ctk.CTkOptionMenu(row1, variable=self._arch_var,
                          values=["64-bit", "32-bit"],
                          width=90).pack(side="left")

        row2 = ctk.CTkFrame(ctrl, fg_color="transparent")
        row2.pack(fill="x", pady=(6, 0))

        self._scan_btn = ctk.CTkButton(row2, text="Scan Pointers", width=130,
                                        command=self._start_scan)
        self._scan_btn.pack(side="left", padx=(0, 8))
        self._stop_btn = ctk.CTkButton(row2, text="Stop", width=70,
                                        command=self._stop_scan,
                                        state="disabled",
                                        fg_color="#553333")
        self._stop_btn.pack(side="left")

        # Progress
        self._progress = ctk.CTkProgressBar(self, mode="determinate")
        self._progress.pack(fill="x", padx=8, pady=(4, 0))
        self._progress.set(0)

        self._status = ctk.CTkLabel(
            self, text="Enter a target address and click Scan Pointers.",
            font=ctk.CTkFont(size=11), anchor="w")
        self._status.pack(fill="x", padx=8, pady=(2, 4))

        # Results tree
        res_frame = ctk.CTkFrame(self)
        res_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        style = ttk.Style()
        style.theme_use("default")
        style.configure("PT.Treeview",
                         background="#1a1a1a", foreground="#dddddd",
                         rowheight=20, fieldbackground="#1a1a1a",
                         borderwidth=0)
        style.configure("PT.Treeview.Heading",
                         background="#222222", foreground="#888888")
        style.map("PT.Treeview",
                  background=[("selected", "#1f538d")])

        cols = ("chain", "base", "offsets", "target")
        self._tree = ttk.Treeview(res_frame, columns=cols,
                                   show="headings", style="PT.Treeview")
        for col, label, width in [
            ("chain",   "Chain",          320),
            ("base",    "Module",         160),
            ("offsets", "Offsets",        200),
            ("target",  "Resolves To",    130),
        ]:
            self._tree.heading(col, text=label)
            self._tree.column(col, width=width, anchor="w")

        vsb = ttk.Scrollbar(res_frame, orient="vertical",
                             command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True)

        self._tree.bind("<Double-1>", self._add_chain_to_table)

        ctx = tk.Menu(self, tearoff=0)
        ctx.add_command(label="Add to Address Table (as INT64)",
                        command=self._add_chain_to_table)
        self._tree.bind(
            "<Button-3>",
            lambda e: (self._tree.selection_set(
                self._tree.identify_row(e.y)),
                ctx.post(e.x_root, e.y_root)),
        )

    def set_target(self, addr: int) -> None:
        self._addr_var.set(f"0x{addr:X}")

    def _start_scan(self) -> None:
        if self._scanning:
            return
        if not self.app.pid:
            messagebox.showwarning("No Process",
                                   "Attach to a process first.", parent=self)
            return

        s = self._addr_var.get().strip()
        try:
            target = int(s, 0)
        except ValueError:
            messagebox.showerror("Invalid address",
                                  f"Cannot parse: {s!r}", parent=self)
            return
        try:
            search_range = int(self._range_var.get().strip(), 0)
        except ValueError:
            search_range = 0x500

        depth    = int(self._depth_var.get())
        ptr_size = 8 if self._arch_var.get() == "64-bit" else 4

        self._scanning = True
        self._scan_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._tree.delete(*self._tree.get_children())
        self._progress.set(0)
        self._status.configure(text="Scanning…")

        def progress_cb(done: int, total: int, msg: str) -> None:
            if total > 0:
                self.after(0, lambda: (
                    self._progress.set(done / total),
                    self._status.configure(text=msg),
                ))

        def worker():
            scanner = PointerScanner(
                pid=self.app.pid,
                target_addr=target,
                max_depth=depth,
                pointer_range=search_range,
                ptr_size=ptr_size,
                max_results=500,
                progress_callback=progress_cb,
            )
            self._scanner = scanner
            try:
                chains = scanner.scan()
            except Exception as e:
                self.after(0, lambda: (
                    messagebox.showerror("Scan Error", str(e), parent=self),
                    self._finish_scan([]),
                ))
                return
            self.after(0, lambda: self._finish_scan(chains))

        threading.Thread(target=worker, daemon=True).start()

    def _stop_scan(self) -> None:
        if self._scanner:
            self._scanner.stop()

    def _finish_scan(self, chains: list[PointerChain]) -> None:
        self._scanning = False
        self._chains = chains
        self._scan_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")
        self._progress.set(1.0)
        self._status.configure(text=f"Found {len(chains)} pointer chains.")
        self._populate(chains)

    def _populate(self, chains: list[PointerChain]) -> None:
        self._tree.delete(*self._tree.get_children())
        for i, chain in enumerate(chains):
            offsets_str = " → ".join(
                f"+0x{abs(o):X}" if o >= 0 else f"-0x{abs(o):X}"
                for o in chain.offsets
            )
            self._tree.insert(
                "", "end",
                iid=str(i),
                values=(
                    chain.display(),
                    f"{chain.base_module}+0x{chain.base_offset:X}",
                    offsets_str,
                    f"0x{chain.final_address:X}",
                ),
            )

    def _add_chain_to_table(self, event=None) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        for iid in sel:
            idx = int(iid)
            if idx < len(self._chains):
                chain = self._chains[idx]
                entry = ScanEntry(
                    address=chain.final_address,
                    previous_bytes=b"",
                )
                self.app.address_table.add_entry(
                    entry, DataType.INT64,
                    description=chain.display(),
                )
