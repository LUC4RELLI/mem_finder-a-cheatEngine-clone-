#!/usr/bin/env python3
"""
NAS_TRAP — Python memory editor / scanner (Cheat Engine clone for Linux x86_64)

Usage:
    sudo python main.py

Requirements:
    pip install customtkinter psutil numpy capstone

Permissions:
    - Memory reading (process_vm_readv) requires same UID or root.
    - Hardware watchpoints require ptrace access.
      Either run as root, or allow ptrace:
        echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
"""
import sys
import os

# ── Sanity checks ──────────────────────────────────────────────────────────────

if sys.platform != "linux":
    print("NAS_TRAP currently supports Linux x86_64 only.", file=sys.stderr)
    sys.exit(1)

if os.geteuid() != 0:
    print(
        "Warning: not running as root.\n"
        "Memory reading may work for processes of the same user,\n"
        "but hardware watchpoints (ptrace) may fail.\n"
        "Consider: sudo python main.py\n"
    )

# ── Import and launch ──────────────────────────────────────────────────────────

try:
    import customtkinter
except ImportError:
    print("customtkinter not found. Install with: pip install customtkinter",
          file=sys.stderr)
    sys.exit(1)

try:
    import numpy
except ImportError:
    print("numpy not found. Install with: pip install numpy", file=sys.stderr)
    sys.exit(1)

try:
    import psutil
except ImportError:
    print("psutil not found. Install with: pip install psutil", file=sys.stderr)
    sys.exit(1)

# Add project root to path so imports work regardless of cwd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gui.app import App


def main() -> None:
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
