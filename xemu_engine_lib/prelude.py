"""Shared imports and platform definitions.

Extracted verbatim from xemu_cheat_engine.py lines 12-46.
"""
import os, sys, time, socket, struct, platform, threading, re, configparser, json
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk, filedialog

# Ownership reclamation for files written while running under sudo. Imported
# here rather than per-module because prelude re-exports its whole namespace,
# so every `from .prelude import *` picks it up. The path insert covers the
# case of a module being imported directly rather than through the launcher.
try:
    import xemu_privs
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import xemu_privs

try:
    import numpy as np
    _HAVE_NUMPY = True
except ImportError:
    _HAVE_NUMPY = False

# _HAVE_NUMPY reads like a graceful-degradation flag, but it is not one: the
# page-table walker, the scanner and the function index all call np.* with no
# guard. Without numpy the app imports cleanly and then dies with a NameError
# on the first address translation - which looks like a bug in the tool rather
# than a missing package. Say so up front instead.
#
# Deliberately NOT a silent pure-Python fallback: the equivalent walker
# benchmarks at ~10.8 s against ~28 ms for the numpy one on a 64 MB image, so
# "working" would mean an eleven-second freeze on every page map rebuild.
if not _HAVE_NUMPY:
    _PY = os.path.basename(sys.executable) or "python3"
    _PIP_CMD = f"{_PY} -m pip install numpy"
    _APT_CMD = "sudo apt install python3-numpy"

    print(f"\n[-] NumPy is required by the Xemu Cheat Engine and is not "
          f"installed.\n\n    Install it with:\n\n        {_PIP_CMD}\n\n"
          f"    On Debian/Ubuntu/Mint you may need this instead:\n\n"
          f"        {_APT_CMD}\n\n    (The Xemu Cheats Trainer does not need "
          f"NumPy and runs without it.)\n", file=sys.stderr)

    def _numpy_dialog():
        """
        A dialog with the install commands in copyable fields.

        Not messagebox.showerror: its text cannot be selected, so the user
        would have to retype the command from a screenshot. Each command sits
        in a readonly Entry with its own Copy button.
        """
        root = tk.Tk()
        root.title("Missing dependency: NumPy")
        root.configure(bg="#212121")
        root.resizable(False, False)

        tk.Label(root, bg="#212121", fg="#FFFFFF", justify="left",
                 font=("Helvetica", 11, "bold"),
                 text="NumPy is required and is not installed."
                 ).pack(anchor="w", padx=16, pady=(16, 2))
        tk.Label(root, bg="#212121", fg="#B0BEC5", justify="left",
                 font=("Helvetica", 9),
                 text="The Cheat Engine uses it for page-table translation "
                      "and scanning.\nRun one of these, then start the "
                      "Cheat Engine again."
                 ).pack(anchor="w", padx=16, pady=(0, 10))

        def add_cmd(label, cmd):
            tk.Label(root, text=label, bg="#212121", fg="#B0BEC5",
                     font=("Helvetica", 9)).pack(anchor="w", padx=16)
            row = tk.Frame(root, bg="#212121")
            row.pack(fill="x", padx=16, pady=(2, 10))
            var = tk.StringVar(value=cmd)
            ent = tk.Entry(row, textvariable=var, font=("Courier", 10),
                           bg="#151515", fg="#A5D6A7", relief="flat",
                           readonlybackground="#151515", width=40)
            ent.pack(side="left", fill="x", expand=True, ipady=4)
            ent.config(state="readonly")
            # Select-all on click, so click-then-Ctrl+C works for anyone who
            # ignores the button.
            ent.bind("<Button-1>",
                     lambda e, w=ent: (w.select_range(0, "end"), "break")[1])
            btn = tk.Button(row, text="Copy", bg="#4CAF50", fg="white",
                            relief="flat", padx=10,
                            font=("Helvetica", 9, "bold"))

            def do_copy(c=cmd, b=btn):
                root.clipboard_clear()
                root.clipboard_append(c)
                root.update()          # push it to the X11/Win32 clipboard now
                b.config(text="Copied", bg="#2E7D32")
                root.after(1200, lambda: b.config(text="Copy", bg="#4CAF50"))

            btn.config(command=do_copy)
            btn.pack(side="left", padx=(6, 0))

        add_cmd("pip (most systems):", _PIP_CMD)
        add_cmd("Debian / Ubuntu / Mint, if pip refuses:", _APT_CMD)

        tk.Label(root, bg="#212121", fg="#FF9800", justify="left",
                 font=("Helvetica", 8),
                 text="Paste it before closing this window - on Linux the "
                      "clipboard is\nowned by this process and may be lost "
                      "when it exits.\n\nThe Xemu Cheats Trainer does not "
                      "need NumPy and runs without it."
                 ).pack(anchor="w", padx=16, pady=(0, 10))

        tk.Button(root, text="Quit", command=root.destroy, bg="#f44336",
                  fg="white", relief="flat", padx=16, pady=4,
                  font=("Helvetica", 9, "bold")).pack(pady=(0, 14))

        root.update_idletasks()
        w, h = root.winfo_width(), root.winfo_height()
        root.geometry(f"+{(root.winfo_screenwidth() - w) // 2}"
                      f"+{(root.winfo_screenheight() - h) // 3}")
        root.mainloop()

    # Guarded: with no display, or no tkinter at all, the console text above
    # is still the useful output and a crash here would bury it.
    try:
        _numpy_dialog()
    except Exception:                                          # noqa: BLE001
        pass
    sys.exit(1)

# --------------------------------------------------------------------------
# Windows‑only imports and definitions (only used if OS is Windows)
# --------------------------------------------------------------------------
if platform.system() == "Windows":
    import ctypes
    from ctypes import wintypes
    # Constants for process access and memory scanning
    PROCESS_ALL_ACCESS   = 0x001F0FFF
    MEM_COMMIT           = 0x1000
    PAGE_READWRITE       = 0x04
    TH32CS_SNAPPROCESS   = 0x00000002

    class PROCESSENTRY32(ctypes.Structure):
        """Structure used by CreateToolhelp32Snapshot to enumerate processes."""
        _fields_ = [
            ("dwSize",              wintypes.DWORD),
            ("cntUsage",            wintypes.DWORD),
            ("th32ProcessID",       wintypes.DWORD),
            ("th32ModuleID",        ctypes.c_void_p),
            ("cntThreads",          wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase",      wintypes.LONG),
            ("dwFlags",             wintypes.DWORD),
            ("szExeFile",           ctypes.c_char * 260)
        ]


# ------------------------------------------------------------------
# Re-export EVERYTHING, including single-underscore names such as
# _HAVE_NUMPY, so `from .prelude import *` reproduces the original
# module namespace exactly. `import *` skips underscore names unless
# __all__ says otherwise.
#
# Computed at runtime, not hard-coded: the platform-conditional names
# (ctypes, wintypes, PROCESSENTRY32, PROCESS_ALL_ACCESS, ...) exist
# only on Windows, exactly as in the original script.
# ------------------------------------------------------------------
__all__ = [_n for _n in dir() if not _n.startswith('__')]
