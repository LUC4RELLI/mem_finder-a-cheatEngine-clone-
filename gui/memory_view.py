"""
Hex memory viewer with inline byte editing.
"""
from __future__ import annotations
import time
import tkinter as tk
from tkinter import messagebox
from typing import Optional

import customtkinter as ctk

from core.memory_io import read_memory, write_memory

BYTES_PER_ROW = 16
ROWS_TO_SHOW  = 24
PAGE_SIZE     = BYTES_PER_ROW * ROWS_TO_SHOW  # 384 bytes per page


class MemoryViewFrame(ctk.CTkFrame):
    def __init__(self, parent, app, **kwargs):
        super().__init__(parent, **kwargs)
        self.app = app
        self._base_addr: int = 0
        self._data: bytes = b""
        self._recently_written: set[int] = set()  # byte offsets
        self._build_ui()

    def _build_ui(self) -> None:
        # Nav bar
        nav = ctk.CTkFrame(self, fg_color="transparent")
        nav.pack(fill="x", padx=8, pady=(8, 4))

        ctk.CTkLabel(nav, text="Address:").pack(side="left", padx=(0, 4))
        self._addr_var = tk.StringVar()
        addr_entry = ctk.CTkEntry(nav, textvariable=self._addr_var, width=180)
        addr_entry.pack(side="left", padx=(0, 6))
        addr_entry.bind("<Return>", lambda _: self._go_to_address())

        ctk.CTkButton(nav, text="Go", width=50,
                      command=self._go_to_address).pack(side="left", padx=(0, 8))
        ctk.CTkButton(nav, text="◀ Prev", width=70,
                      command=self._prev_page).pack(side="left", padx=(0, 4))
        ctk.CTkButton(nav, text="Next ▶", width=70,
                      command=self._next_page).pack(side="left", padx=(0, 8))
        ctk.CTkButton(nav, text="Refresh", width=80,
                      command=self._refresh).pack(side="left")

        # Hex view — using a Text widget for monospace display
        view_frame = ctk.CTkFrame(self)
        view_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self._text = tk.Text(
            view_frame,
            font=("Courier New", 11),
            bg="#1a1a1a", fg="#dddddd",
            insertbackground="#dddddd",
            selectbackground="#1f538d",
            relief="flat",
            padx=8, pady=6,
            state="disabled",
            cursor="xterm",
        )
        vsb = tk.Scrollbar(view_frame, command=self._text.yview)
        self._text.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._text.pack(fill="both", expand=True)

        # Tags
        self._text.tag_configure("header", foreground="#888888")
        self._text.tag_configure("written", foreground="#44ff88",
                                  background="#1a3a1a")
        self._text.tag_configure("selected_byte",
                                  background="#1f538d")
        self._text.tag_configure("addr_col", foreground="#666699")

        self._text.bind("<Button-1>", self._on_click)

        # Status
        self._status = ctk.CTkLabel(
            self, text="Enter an address and press Go.",
            font=ctk.CTkFont(size=11), anchor="w")
        self._status.pack(fill="x", padx=8, pady=(0, 4))

    def navigate_to(self, address: int) -> None:
        self._base_addr = address & ~(BYTES_PER_ROW - 1)
        self._addr_var.set(f"0x{address:X}")
        self._refresh()

    def _go_to_address(self) -> None:
        s = self._addr_var.get().strip()
        try:
            addr = int(s, 0)
        except ValueError:
            messagebox.showerror("Invalid address", f"Cannot parse: {s!r}",
                                  parent=self)
            return
        self.navigate_to(addr)

    def _prev_page(self) -> None:
        self._base_addr = max(0, self._base_addr - PAGE_SIZE)
        self._addr_var.set(f"0x{self._base_addr:X}")
        self._refresh()

    def _next_page(self) -> None:
        self._base_addr += PAGE_SIZE
        self._addr_var.set(f"0x{self._base_addr:X}")
        self._refresh()

    def _refresh(self) -> None:
        if not self.app.pid or self._base_addr == 0:
            return
        data = read_memory(self.app.pid, self._base_addr, PAGE_SIZE)
        if data is None:
            data = b"\x00" * PAGE_SIZE
            self._status.configure(
                text=f"0x{self._base_addr:X} — unreadable region")
        else:
            self._status.configure(
                text=f"0x{self._base_addr:X}  ({len(data)} bytes)")
        self._data = data
        self._render()

    def _render(self) -> None:
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")

        # Header
        header = "Address          " + " ".join(f"{i:02X}" for i in range(BYTES_PER_ROW))
        header += "  " + "".join(f"{i:X}" for i in range(BYTES_PER_ROW)) + "\n"
        self._text.insert("end", header, "header")

        for row in range(len(self._data) // BYTES_PER_ROW):
            offset = row * BYTES_PER_ROW
            addr = self._base_addr + offset
            row_bytes = self._data[offset: offset + BYTES_PER_ROW]

            # Address column
            self._text.insert("end", f"0x{addr:016X}  ", "addr_col")

            # Hex bytes
            for i, b in enumerate(row_bytes):
                tag = "written" if (offset + i) in self._recently_written else ""
                self._text.insert("end", f"{b:02X} ", tag)

            # ASCII
            self._text.insert("end", " ")
            for i, b in enumerate(row_bytes):
                ch = chr(b) if 0x20 <= b < 0x7F else "."
                tag = "written" if (offset + i) in self._recently_written else ""
                self._text.insert("end", ch, tag)

            self._text.insert("end", "\n")

        self._text.configure(state="disabled")

    def _on_click(self, event) -> None:
        """Identify clicked byte and open edit dialog."""
        if not self._data:
            return
        idx = self._text.index(f"@{event.x},{event.y}")
        row_str, col_str = idx.split(".")
        row = int(row_str) - 2  # row 1 is header
        if row < 0:
            return
        # Hex section: starts at col 18, each byte takes 3 chars
        col = int(col_str)
        hex_start = 18
        hex_end = hex_start + BYTES_PER_ROW * 3
        if hex_start <= col < hex_end:
            byte_idx = (col - hex_start) // 3
        else:
            return

        offset = row * BYTES_PER_ROW + byte_idx
        if offset >= len(self._data):
            return

        addr = self._base_addr + offset
        current_hex = f"{self._data[offset]:02X}"
        new_hex = tk.simpledialog.askstring(
            "Edit Byte",
            f"Address: 0x{addr:X}\nCurrent: 0x{current_hex}\n\nNew hex value (1 byte):",
            initialvalue=current_hex,
            parent=self,
        )
        if new_hex is None:
            return
        try:
            new_val = int(new_hex.strip(), 16)
            if not 0 <= new_val <= 0xFF:
                raise ValueError("Must be 0x00–0xFF")
            if write_memory(self.app.pid, addr, bytes([new_val])):
                self._recently_written.add(offset)
                self.after(2000, lambda o=offset: (
                    self._recently_written.discard(o), self._render()))
                self._refresh()
        except Exception as e:
            messagebox.showerror("Error", str(e), parent=self)
