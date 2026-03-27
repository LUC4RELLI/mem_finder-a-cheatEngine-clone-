"""
Main application window.
"""
from __future__ import annotations
import tkinter as tk
from tkinter import messagebox
from typing import Optional

import customtkinter as ctk

from core.process_manager import ProcessInfo, attach, detach, is_process_alive
from gui.process_dialog import ProcessDialog
from gui.scanner_frame import ScannerFrame
from gui.address_table import AddressTableFrame
from gui.memory_view import MemoryViewFrame
from gui.watchpoint_frame import WatchpointFrame
from gui.pointer_frame import PointerFrame


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("NAS_TRAP — Memory Editor")
        self.geometry("1100x760")
        self.minsize(900, 600)

        self.pid: Optional[int] = None
        self._process_info: Optional[ProcessInfo] = None

        self._build_ui()
        self._schedule_process_check()

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        # ── Top bar ───────────────────────────────────────────────────────────
        topbar = ctk.CTkFrame(self, height=40, corner_radius=0)
        topbar.pack(fill="x", side="top")
        topbar.pack_propagate(False)

        ctk.CTkLabel(
            topbar,
            text="NAS_TRAP",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#4a9eff",
        ).pack(side="left", padx=12)

        self._proc_btn = ctk.CTkButton(
            topbar,
            text="[ No Process — Click to Attach ]",
            command=self._open_process_dialog,
            fg_color="#333333",
            hover_color="#444444",
            text_color="#aaaaaa",
            width=320,
        )
        self._proc_btn.pack(side="left", padx=6, pady=6)

        self._detach_btn = ctk.CTkButton(
            topbar, text="Detach", width=70,
            command=self._detach,
            fg_color="#553333",
            hover_color="#663333",
            state="disabled",
        )
        self._detach_btn.pack(side="left", padx=(0, 6))

        self._status_label = ctk.CTkLabel(
            topbar, text="", font=ctk.CTkFont(size=11),
            text_color="#888888",
        )
        self._status_label.pack(side="left", padx=6)

        # ── Main layout: left panel (scanner + address table) + right tabs ───
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.pack(fill="both", expand=True, padx=6, pady=6)

        # Left: scanner + address table stacked
        left = ctk.CTkFrame(main, width=480)
        left.pack(side="left", fill="both", expand=False, padx=(0, 4))
        left.pack_propagate(False)

        self.scanner_frame = ScannerFrame(left, app=self)
        self.scanner_frame.pack(fill="both", expand=False)

        separator = ctk.CTkFrame(left, height=2, fg_color="#333333")
        separator.pack(fill="x", padx=4, pady=2)

        self.address_table = AddressTableFrame(left, app=self)
        self.address_table.pack(fill="both", expand=True)

        # Right: tabview for Memory View, Watchpoints, Pointer Scanner
        self._tabs = ctk.CTkTabview(main)
        self._tabs.pack(side="left", fill="both", expand=True)

        self._tabs.add("Memory View")
        self._tabs.add("Watchpoints")
        self._tabs.add("Pointer Scanner")

        self.memory_view = MemoryViewFrame(
            self._tabs.tab("Memory View"), app=self)
        self.memory_view.pack(fill="both", expand=True)

        self.watchpoint_frame = WatchpointFrame(
            self._tabs.tab("Watchpoints"), app=self)
        self.watchpoint_frame.pack(fill="both", expand=True)

        self.pointer_frame = PointerFrame(
            self._tabs.tab("Pointer Scanner"), app=self)
        self.pointer_frame.pack(fill="both", expand=True)

    # ── Process management ────────────────────────────────────────────────────

    def _open_process_dialog(self) -> None:
        ProcessDialog(self, on_attach=self._do_attach)

    def _do_attach(self, proc: ProcessInfo) -> None:
        # Detach from previous if any
        if self.pid:
            try:
                detach(self.pid)
            except Exception:
                pass

        self.pid = proc.pid
        self._process_info = proc
        self._proc_btn.configure(
            text=f"PID {proc.pid}: {proc.name} ({proc.arch}-bit)",
            text_color="#44bb44",
            fg_color="#1a3a1a",
        )
        self._detach_btn.configure(state="normal")
        self._status_label.configure(
            text=f"Attached  |  User: {proc.username}")
        self.watchpoint_frame.on_process_changed()

    def _detach(self) -> None:
        if not self.pid:
            return
        try:
            self.watchpoint_frame.on_process_changed()
            detach(self.pid)
        except Exception:
            pass
        self.pid = None
        self._process_info = None
        self._proc_btn.configure(
            text="[ No Process — Click to Attach ]",
            text_color="#aaaaaa",
            fg_color="#333333",
        )
        self._detach_btn.configure(state="disabled")
        self._status_label.configure(text="")

    def _schedule_process_check(self) -> None:
        if self.pid and not is_process_alive(self.pid):
            self._status_label.configure(
                text="Process has exited!", text_color="#ff4444")
            self.pid = None
        self.after(2000, self._schedule_process_check)

    # ── Cross-frame navigation helpers ───────────────────────────────────────

    def open_watchpoint_for(self, addr: int) -> None:
        """Switch to Watchpoints tab and pre-fill the address."""
        self._tabs.set("Watchpoints")
        self.watchpoint_frame.add_watchpoint_for_address(addr)

    def open_memory_view_at(self, addr: int) -> None:
        """Switch to Memory View tab and navigate to address."""
        self._tabs.set("Memory View")
        self.memory_view.navigate_to(addr)

    def open_pointer_scanner_for(self, addr: int) -> None:
        """Switch to Pointer Scanner tab and pre-fill target address."""
        self._tabs.set("Pointer Scanner")
        self.pointer_frame.set_target(addr)
