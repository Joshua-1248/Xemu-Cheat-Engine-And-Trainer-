"""Guest page-table translation (on-demand walker).

Extracted verbatim from xemu_cheats_trainer.py.
"""
from .prelude import *  # noqa: F401,F403
import os, sys, time, struct, platform, threading, re, json, configparser
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog


class XboxPageMap:
    """
    Guest virtual -> physical translation from the Xbox page tables.

    Needed because every address a code writes is a physical offset into xemu's
    RAM block, while the pointers a game stores are virtual addresses. On the
    original Xbox these differ: virtual 0x00010000 sat at physical 0x005B2000 in
    a DOOM 3 dump. The page directory is at physical 0x0000F000.
    """

    NONE = 0xFFFFFFFF
    PD_PHYS = 0x0000F000

    @classmethod
    def on_demand(cls, mem, mem_file=None):
        """
        A translator that walks the tables per lookup instead of building a map.

        Building the full map reads all 128 MB (~4 s). A cheat needs two or
        three translations per tick, and each one is a 4-byte PDE read plus a
        4-byte PTE read. Walking on demand is ~8 bytes per lookup rather than
        128 MB per rebuild, which also means staleness stops mattering: every
        lookup already reads the live tables.
        """
        obj = cls.__new__(cls)
        obj.v2p = None
        obj.mem = mem
        obj.mem_file = mem_file
        obj.ram_size = mem.xbox_ram_size_mb * 1024 * 1024
        obj._cache = {}
        return obj

    def _rd32_phys(self, pa):
        raw = self.mem.read_mem(self.mem.xbox_ram_base + pa, 4, self.mem_file)
        return None if len(raw) < 4 else struct.unpack("<I", raw)[0]

    def _walk(self, va):
        """Translate one address by reading the live page tables."""
        page = va >> 12
        hit = self._cache.get(page)
        if hit is not None:
            return hit + (va & 0xFFF)
        pde = self._rd32_phys(self.PD_PHYS + ((va >> 22) * 4))
        if pde is None or not (pde & 1):
            return None
        if pde & 0x80:                                  # 4 MB large page
            base = (pde & 0xFFC00000) | (va & 0x003FF000)
        else:
            pt = pde & 0xFFFFF000
            pte = self._rd32_phys(pt + (((va >> 12) & 0x3FF) * 4))
            if pte is None or not (pte & 1):
                return None
            base = pte & 0xFFFFF000
        if base >= self.ram_size:
            return None
        # Small cache, cleared whenever the guest re-pages (see invalidate()).
        if len(self._cache) < 4096:
            self._cache[page] = base
        return base + (va & 0xFFF)

    def invalidate(self):
        self._cache.clear()

    def __init__(self, dump):
        n = len(dump)
        u32 = struct.unpack(f'<{(n // 4)}I', dump[:(n // 4) * 4])
        v2p = [self.NONE] * (1 << 20)
        pd = u32[self.PD_PHYS // 4: self.PD_PHYS // 4 + 1024]
        for i in range(1024):
            e = pd[i]
            if not (e & 1):
                continue
            if e & 0x80:                                   # 4 MB large page
                fr = (e & 0xFFC00000) >> 12
                for k in range(1024):
                    v2p[(i << 10) + k] = fr + k
                continue
            pt = e & 0xFFFFF000
            if pt + 0x1000 > n:
                continue
            ptes = u32[pt // 4: pt // 4 + 1024]
            for k in range(1024):
                if ptes[k] & 1:
                    v2p[(i << 10) + k] = ptes[k] >> 12
        self.v2p = v2p
        self.ram_size = n

    @property
    def valid(self):
        if self.v2p is None:
            return self._walk(0x00010000) is not None
        return sum(1 for v in self.v2p[:0x2000] if v != self.NONE) > 64

    def to_phys(self, va):
        if va < 0 or va > 0xFFFFFFFF:
            return None
        if self.v2p is None:                # on-demand mode
            return self._walk(va)
        p = self.v2p[va >> 12]
        if p == self.NONE:
            return None
        p = p * 0x1000 + (va & 0xFFF)
        return p if p < self.ram_size else None

