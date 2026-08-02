"""Shared imports and platform definitions.

Extracted verbatim from xemu_cheats_trainer.py lines 14-38.
"""
import os, sys, time, struct, platform, threading, re, json, configparser
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog

# Ownership reclamation for files written while running under sudo. Imported
# here rather than per-module because prelude re-exports its whole namespace,
# so every `from .prelude import *` picks it up. The path insert covers the
# case of a module being imported directly rather than through the launcher.
try:
    import xemu_privs
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import xemu_privs

# ----- Windows‑only imports -----
if platform.system() == "Windows":
    import ctypes
    from ctypes import wintypes
    PROCESS_ALL_ACCESS   = 0x001F0FFF
    MEM_COMMIT           = 0x1000
    PAGE_READWRITE       = 0x04
    TH32CS_SNAPPROCESS   = 0x00000002

    class PROCESSENTRY32(ctypes.Structure):
        # Must match tlhelp32.h field for field. th32DefaultHeapID was missing
        # and th32ModuleID stood in for it as a pointer, which left szExeFile
        # 4 bytes early: Process32First filled the real layout, the name was
        # read from the wrong offset, and "xemu.exe" never matched. Attaching
        # on Windows could not work at all.
        _fields_ = [
            ("dwSize",              wintypes.DWORD),
            ("cntUsage",            wintypes.DWORD),
            ("th32ProcessID",       wintypes.DWORD),
            ("th32DefaultHeapID",   ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID",        wintypes.DWORD),
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
