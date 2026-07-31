"""Xbox memory region map, XBE parsing, address description.

Extracted verbatim from xemu_cheat_engine.py.
"""
from .prelude import *  # noqa: F401,F403
import os, sys, time, socket, struct, platform, threading, re, configparser, json
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk, filedialog
try:
    import numpy as np
    _HAVE_NUMPY = True
except ImportError:
    _HAVE_NUMPY = False


RAM_MASK_LO = 0x00010000        # below this is kernel/null page, never a game pointer

KSEG_BASE   = 0x80000000

def detect_xbe_region(dump, ram_size):
    """
    Locate the loaded XBE image by finding its header in low RAM.
    Returns (base, size) as RAM offsets, or a conservative fallback.
    """
    # The XBE is loaded at its own declared base; scan page-aligned low memory
    # for the 'XBEH' magic rather than assuming 0x00010000.
    # The image is wherever the loader put it physically - in a real dump
    # that was 0x005B2000, well past the 4 MB this used to search.
    limit = min(ram_size, 0x02000000)
    for off in range(0x00010000, limit, 0x1000):
        if dump[off:off + 4] != b'XBEH':
            continue
        try:
            base = struct.unpack_from('<I', dump, off + 0x104)[0]
            size = struct.unpack_from('<I', dump, off + 0x10C)[0]
        except struct.error:
            continue
        base &= 0x0FFFFFFF
        if not (0x1000 <= size <= ram_size):
            continue
        # The header need NOT sit at its declared base: the Xbox maps the XBE
        # through page tables, so its physical offset in xemu's RAM block is
        # wherever the loader happened to put it. Trust the offset we found it
        # at, not the virtual base it declares.
        return off, min(size, ram_size - off)
    return None, None

XBOX_SCAN_REGIONS = [
    ("All physical RAM",                      None,       None,       False),
    ("[V] User space (heap + XBE)",           0x00010000, 0x08000000, True),
    ("[V] XBE image only (statics)",          0x00010000, 0x00800000, True),
    ("[V] User heap only",                    0x00720000, 0x08000000, True),
    ("[V] Kernel window 0x80000000+",         0x80000000, 0x88000000, True),
    ("[P] Physical 0-64MB",                   0x00000000, 0x04000000, False),
    ("[P] Physical 64-128MB",                 0x04000000, 0x08000000, False),
    ("Custom range...",                       -1,         -1,         False),
]

XBOX_REGIONS = [
    ("00010000  XBE image (code, .rdata, .data)", 0x00010000, True,  True),
    ("00720000  User heap",                       0x00720000, True,  True),
    ("80000000  Physical RAM (kernel window)",    0x80000000, True,  True),
    ("B0000000  Kernel window (upper)",           0xB0000000, True,  True),
    ("C0000000  Page tables (self-map)",          0xC0000000, True,  True),
    ("C0300000  Page directory (self-map)",       0xC0300000, True,  True),
    ("D0008000  Kernel data",                     0xD0008000, True,  True),
    ("F0000000  GPU aperture / tiled memory",     0xF0000000, True,  False),
    ("FD000000  NV2A GPU registers",              0xFD000000, True,  False),
    ("FE800000  APU / ACI registers",             0xFE800000, True,  False),
    ("FF000000  Flash ROM (BIOS)",                0xFF000000, True,  False),
    ("--- physical offsets ---",                  None,       False, True),
    ("00000000  RAM start (physical)",            0x00000000, False, True),
    ("0000F000  Page directory (physical)",       0x0000F000, False, True),
    ("03F00000  Top of 64MB RAM",                 0x03F00000, False, True),
]

def parse_xbe_sections(dump, xbe_phys):
    """
    [(name, virt_lo, virt_hi, writable, executable)] for the loaded XBE.

    Used to describe a pointer base in words a human can act on: a base in
    '.data' is a good permanent anchor, one in '.rdata' is a const table, and
    one outside the image entirely will not survive a reboot.
    """
    try:
        base = struct.unpack_from('<I', dump, xbe_phys + 0x104)[0]
        nsec = struct.unpack_from('<I', dump, xbe_phys + 0x11C)[0]
        secv = struct.unpack_from('<I', dump, xbe_phys + 0x120)[0]
        delta = xbe_phys - base
        out = []
        for k in range(min(nsec, 64)):
            o = secv + delta + k * 0x38
            if o + 0x38 > len(dump):
                break
            flags, va, vsz = struct.unpack_from('<III', dump, o)
            nptr = struct.unpack_from('<I', dump, o + 0x14)[0]
            nm = dump[nptr + delta:nptr + delta + 20].split(b'\0')[0]
            out.append((nm.decode('latin1', 'replace'), va, va + vsz,
                        bool(flags & 1), bool(flags & 4)))
        return out
    except Exception:
        return []

def describe_address(va, sections, pagemap):
    """One-line plain-English account of where a virtual address lives."""
    for nm, lo, hi, w, x in sections:
        if lo <= va < hi:
            kind = "writable data" if w and not x else \
                   ("code" if x and not w else
                    ("code+data" if x and w else "read-only data"))
            return f"{nm} ({kind}) inside the XBE image - fixed every boot"
    if 0x00010000 <= va < 0x00800000:
        return "XBE image, outside any named section - fixed every boot"
    if 0x80000000 <= va < 0x88000000:
        return "kernel contiguous-memory window - moves between runs"
    if 0xC0000000 <= va < 0xC0400000:
        return "page tables - not a usable cheat base"
    if 0xD0000000 <= va < 0xD1000000:
        return "kernel data - moves between runs"
    if va >= 0xF0000000:
        return "GPU aperture / hardware registers"
    return "game heap - moves every load, needs a pointer chain"

