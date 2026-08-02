"""Core engine: process attach, RAM read/write, value scanning, freeze loop.

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
from .pagemap import XboxPageMap  # noqa: F401


class XemuTrainerEngine:
    """
    Core engine that handles:
      - Finding the Xemu process and the host address of its Xbox RAM.
      - Reading / writing the emulated Xbox's RAM.
      - Value scanning (first / next scan with various scan modes).
      - Freeze trainer loop (writes a fixed value repeatedly).
      - Pointer chain resolution (supports multi‑level pointers).
    """

    def __init__(self):
        # Process & memory information
        self.pid               = None           # Process ID of the Xemu emulator
        self.xbox_ram_base     = None           # Host virtual address where Xbox RAM starts
        self.running           = False          # Controls the freeze trainer thread
        self._trainer_gen      = 0              # Only the newest freeze thread may run
        self.pagemap           = None           # XboxPageMap, built on demand
        self._pagemap_probe    = None           # PDE fingerprint when map was built
        self._pagemap_time     = 0.0            # when the map was built
        self._pagemap_check    = 0.0            # last staleness probe
        self._pagemap_stale    = False          # latched verdict, cleared on rebuild
        self._memfh            = None           # shared /proc/<pid>/mem handle
        self._memfh_pid        = None
        self.scan_pagemask     = None           # bool per physical page, None = all
        self.scan_bytes        = None           # optional exact (lo, hi) byte range
        self.scan_region_name  = "All physical RAM"
        self.scan_virtual      = False          # report results as virtual?
        self.os_type           = platform.system()  # "Linux" or "Windows"
        # Every platform branch below is Linux-or-Windows with a silent no-op
        # fallthrough, so on macOS reads return zeros and writes disappear
        # without raising. Name it so the UI can report it instead of looking
        # attached-but-broken.
        self.unsupported       = self.os_type not in ("Linux", "Windows")
        self.win_process_handle = None          # (Windows) OpenProcess handle

        # Address table – each entry is a list with these elements:
        # [offset, desc, type, freeze, lock_val, is_ptr, base, offsets, static_off, group, id]
        self.address_table = []
        self._next_entry_id = 1

        # Memory scan state
        self.xbox_ram_size_mb   = 0
        self.scan_results       = []   # Offsets that matched the last scan
        self.previous_snapshot  = None # Full RAM dump from first scan (bytes)
        self.scan_raw_prev      = {}   # offset -> raw bytes (used for next scan)
        self.scan_values        = {}   # offset -> formatted previous value string

        # NEW: remembers the exact item width (in bytes) that was used for the
        # scan currently represented by self.scan_results, so that later Next
        # Scan calls can't silently shrink it just because the value entry box
        # happens to be empty (this was corrupting String / Array-of-Bytes
        # comparison scans - see _get_type_params usage below).
        self._scan_item_size    = None
        # NEW: the last full RAM dump taken (bytes). Used as the numpy-vectorized
        # "old value" baseline for numeric comparison scans, replacing the
        # per-offset Python loop that used to make Next Scan unusably slow
        # right after an Unknown Initial Value search.
        self._last_full_dump    = None

    # ----------------------------------------------------------------------
    def find_xemu_base(self):
        """
        Locate the Xemu process and the start of its emulated Xbox RAM.
        Returns True on success, False otherwise.
        """
        if self.os_type == "Linux":
            return self._find_xemu_base_linux()
        elif self.os_type == "Windows":
            return self._find_xemu_base_windows()
        return False

    # ----------------------------------------------------------------------
    # A full snapshot cannot notice the guest re-paging, so it gets a short
    # life. The on-demand walker re-reads the tables per lookup and expires its
    # own cache, so it only needs the cheap fingerprint check below.
    PAGEMAP_SNAPSHOT_TTL = 2.0      # seconds
    PAGEMAP_PROBE_EVERY  = 0.25     # seconds; rate-limit the 4-byte probe

    def _pd_fingerprint(self, mem_file=None):
        """
        4-byte fingerprint of the guest page directory.

        The PDE covering the XBE image changes whenever the guest rebuilds its
        page tables, which it does on level load and on title restart. Reading
        one dword is enough to notice, and is cheap enough to do inline.
        """
        try:
            off = XboxPageMap.PD_PHYS + ((0x00010000 >> 22) * 4)
            raw = self.read_mem(self.xbox_ram_base + off, 4, mem_file)
            return struct.unpack("<I", raw)[0] if len(raw) >= 4 else None
        except Exception:
            return None

    def pagemap_is_stale(self, mem_file=None):
        """
        Whether the cached translator can still be trusted.

        This check did not exist, and its absence is why the address table got
        stuck showing "Error" until the program was restarted. ensure_pagemap()
        only built a map when there was none, so once one was installed it was
        kept for the life of the process. A virtual-region scan installs a FULL
        snapshot (resolve of scan_pagemask needs the v2p array); after the guest
        re-paged, every pointer chain resolved through that frozen table, every
        dereference read the wrong frame, and resolve_entry returned None -
        which the table renders as "Error". Nothing recovered because nothing
        ever reconsidered the map.
        """
        pm = self.pagemap
        if pm is None:
            return True
        # Latched: once staleness has been established it stays established
        # until a rebuild clears it. Without this the rate limiter below
        # answers False on the very next call, so ensure_pagemap() - which
        # asks again immediately after this returns True - would decline to
        # rebuild and the stale map would survive anyway.
        if self._pagemap_stale:
            return True
        now = time.time()
        # Snapshots go stale on a timer; they have no way to self-heal.
        if getattr(pm, 'v2p', None) is not None and \
                now - self._pagemap_time > self.PAGEMAP_SNAPSHOT_TTL:
            self._pagemap_stale = True
            return True
        if self._pagemap_probe is None:
            self._pagemap_stale = True
            return True
        # Rate-limit: resolve_entry runs per row per refresh, and an
        # unthrottled probe would add a syscall to each one.
        if now - self._pagemap_check < self.PAGEMAP_PROBE_EVERY:
            return False
        self._pagemap_check = now
        cur = self._pd_fingerprint(mem_file)
        if cur is None or cur != self._pagemap_probe:
            self._pagemap_stale = True
            return True
        # Same page directory, but individual pages below it may still have
        # moved; drop the walker's memoised translations to be safe.
        try:
            pm.invalidate()
        except Exception:
            pass
        return False

    def invalidate_pagemap(self):
        """Force the next ensure_pagemap() to rebuild. Call when re-attaching."""
        self.pagemap = None
        self._pagemap_probe = None
        self._pagemap_time = 0.0
        self._pagemap_check = 0.0
        self._pagemap_stale = False

    def ensure_pagemap(self, mem_file=None):
        """
        Make sure a usable translator exists, cheaply.

        Callers used to test `self.pagemap is not None` and silently fall back
        to physical reads when it was None - which produced a "virtual" pointer
        entry that actually read a physical offset and returned zeros. Nothing
        built the map outside the pointer finder, so that was the normal case.

        Now also rebuilds when the cached map has gone stale, rather than
        keeping a dead one forever (see pagemap_is_stale).
        """
        if not self.pid:
            return self.pagemap
        if not self.pagemap_is_stale(mem_file):
            return self.pagemap
        try:
            pm = XboxPageMap.on_demand(self)
            self.pagemap = pm if pm.valid else None
        except Exception:
            self.pagemap = None
        self._pagemap_time = time.time()
        self._pagemap_probe = (self._pd_fingerprint(mem_file)
                               if self.pagemap is not None else None)
        self._pagemap_check = time.time()
        self._pagemap_stale = False
        return self.pagemap

    def ensure_pagemap_full(self, mem_file=None):
        """
        A translator backed by a complete v2p array.

        Only the scan-region code needs this; everything else should use
        ensure_pagemap(), which returns the cheaper on-demand walker.
        """
        pm = self.pagemap
        if pm is not None and getattr(pm, 'v2p', None) is not None and \
                not self.pagemap_is_stale(mem_file):
            return pm
        return self.refresh_pagemap(mem_file)

    def refresh_pagemap(self, mem_file=None):
        """Re-read the guest page tables in full. Installs a snapshot."""
        try:
            maxb = self.xbox_ram_size_mb * 1024 * 1024
            dump = self.read_mem(self.xbox_ram_base, maxb, mem_file)
            pm = XboxPageMap(dump)
            self.pagemap = pm if pm.valid else None
        except Exception:
            self.pagemap = None
        self._pagemap_time = time.time()
        self._pagemap_probe = (self._pd_fingerprint(mem_file)
                               if self.pagemap is not None else None)
        self._pagemap_check = time.time()
        self._pagemap_stale = False
        return self.pagemap

    def read32_virt(self, va, mem_file=None):
        """Read a dword at a guest VIRTUAL address."""
        if self.ensure_pagemap() is None:
            return None
        pa = self.pagemap.to_phys(va)
        if pa is None:
            return None
        raw = self.read_mem(self.xbox_ram_base + pa, 4, mem_file)
        return None if len(raw) < 4 else struct.unpack("<I", raw)[0]

    def resolve_pointer_chain_virt(self, base_va, offsets_list, mem_file=None):
        """
        Follow a chain expressed in guest virtual addresses, returning the final
        PHYSICAL offset so the existing read/write paths keep working.
        """
        if self.ensure_pagemap() is None:
            return None
        cur = self.read32_virt(base_va, mem_file)
        if cur is None:
            return None
        for i, off in enumerate(offsets_list):
            cur = (cur + off) & 0xFFFFFFFF
            if i == len(offsets_list) - 1:
                break
            cur = self.read32_virt(cur, mem_file)
            if cur is None:
                return None
        return self.pagemap.to_phys(cur)

    def resolve_chain_steps(self, entry, mem_file=None):
        """
        Resolve a pointer entry one level at a time.

        Returns a list of steps, each a dict:
            level  - 0 for the slot holding the base pointer, then 1..N
            label  - how to describe it in a menu
            phys   - physical RAM offset to browse to, or None if unresolvable
            value  - the dword read there, when there is one

        Level 0 is where the BASE POINTER ITSELF is stored - not what it points
        at. That distinction is the whole point: to check whether a base is
        still valid you need to look at the slot, not follow it.
        """
        if not entry[5]:
            return [{'level': 0, 'label': 'Address', 'phys': entry[8],
                     'value': None, 'addr': entry[8], 'virtual': False}]
        virtual = bool(entry[11]) if len(entry) > 11 else True
        base, offsets = entry[6], list(entry[7])
        steps = []
        maxb = self.xbox_ram_size_mb * 1024 * 1024

        def to_offset(val):
            if 0x80000000 <= val <= 0x8FFFFFFF:
                return val - 0x80000000
            return val if 0 <= val < maxb else None

        def phys_of(addr):
            if not virtual:
                return addr if 0 <= addr < maxb else None
            pm = self.ensure_pagemap()
            return None if pm is None else pm.to_phys(addr)

        def read32(addr):
            if virtual:
                return self.read32_virt(addr, mem_file)
            off = addr if 0 <= addr < maxb else None
            if off is None:
                return None
            raw = self.read_mem(self.xbox_ram_base + off, 4, mem_file)
            return struct.unpack("<I", raw)[0] if len(raw) >= 4 else None

        base_phys = phys_of(base)
        base_val = read32(base)
        steps.append({'level': 0,
                      'label': f"Base pointer stored at 0x{base:08X}",
                      'phys': base_phys, 'value': base_val,
                      'addr': base, 'virtual': virtual})

        cur = None if base_val is None else (
            base_val if virtual else to_offset(base_val))
        for i, off in enumerate(offsets):
            if cur is None:
                steps.append({'level': i + 1,
                              'label': f"Level {i + 1}: +0x{off:X} "
                                       f"(unresolved)",
                              'phys': None, 'value': None,
                              'addr': None, 'virtual': virtual})
                continue
            cur = (cur + off) & 0xFFFFFFFF if virtual else cur + off
            last = (i == len(offsets) - 1)
            val = None if last else read32(cur)
            steps.append({'level': i + 1,
                          'label': (f"Level {i + 1}: +0x{off:X} "
                                    f"-> 0x{cur:08X}"
                                    + ("  (final value)" if last else "")),
                          'phys': phys_of(cur), 'value': val,
                          'addr': cur, 'virtual': virtual})
            if not last:
                cur = None if val is None else (
                    val if virtual else to_offset(val))
        return steps

    def resolve_entry(self, entry, mem_file=None):
        """
        Resolve any address-table entry to a physical offset.

        Single place where an entry's address space is decided. Call sites used
        to call resolve_pointer_chain() directly, which is physical-only - so a
        virtual pointer displayed "Error" in the table even though the same
        chain resolved fine in the editor.
        """
        if not entry[5]:
            return entry[8]
        virtual = bool(entry[11]) if len(entry) > 11 else True
        if virtual:
            if self.ensure_pagemap() is None:
                return None
            return self.resolve_pointer_chain_virt(entry[6], entry[7], mem_file)
        return self.resolve_pointer_chain(entry[6], entry[7], mem_file)

    def resolve_pointer_chain(self, base_addr, offsets_list, mem_file=None):
        """
        Follow a multi‑level pointer chain.

        base_addr   : the offset of the base pointer (relative to Xbox RAM start)
        offsets_list: list of offsets to add at each level.
                      The last element is the final offset to the actual value.
        Returns the final RAM offset, or None if any dereference fails.
        """
        try:
            max_bounds = self.xbox_ram_size_mb * 1024 * 1024

            def to_offset(val):
                """Convert a full Xbox address (0x8…) to a RAM offset."""
                if 0x80000000 <= val <= 0x8FFFFFFF:
                    return val - 0x80000000
                if 0 <= val < max_bounds:
                    return val
                return None

            # Standard Cheat Engine semantics:
            #   addr = [[[base] + o0] + o1] ... + o_last
            # Every offset in the list follows a dereference, including the
            # last. The previous version dereferenced base WITHOUT applying
            # offsets[0] and skipped a deref before the final offset, so any
            # chain deeper than one level resolved to the wrong address - which
            # is why multi-level entries never worked.
            raw = self.read_mem(self.xbox_ram_base + base_addr, 4, mem_file)
            if len(raw) < 4: return None
            cur = to_offset(struct.unpack("<I", raw)[0])
            if cur is None: return None

            for i, off in enumerate(offsets_list):
                cur = cur + off
                if i == len(offsets_list) - 1:
                    break
                if not (0 <= cur < max_bounds): return None
                raw = self.read_mem(self.xbox_ram_base + cur, 4, mem_file)
                if len(raw) < 4: return None
                cur = to_offset(struct.unpack("<I", raw)[0])
                if cur is None: return None

            res = cur
            return res if 0 <= res < max_bounds else None
        except:
            return None

    # ---- Linux memory‑region search --------------------------------------
    def _find_xemu_base_linux(self):
        """
        Scan /proc for a process named 'xemu' and find its largest
        read‑write anonymous memory region, which is the Xbox RAM.
        """
        for pid in os.listdir('/proc'):
            if not pid.isdigit(): continue
            try:
                with open(f"/proc/{pid}/comm", "r") as f:
                    if "xemu" not in f.read().lower(): continue
            except: continue
            # int(), not the str from listdir. os.kill() rejects a str with
            # TypeError, the bare except in is_alive() swallowed it, and
            # is_alive() therefore returned False on every single call - so
            # the 2-second watchdog tore down and rebuilt the connection
            # forever, briefly clearing xbox_ram_base each time.
            self.pid = int(pid)
            break
        if not self.pid: return False

        candidates = []
        try:
            with open(f"/proc/{self.pid}/maps", "r") as maps:
                for line in maps:
                    if "rw-p" not in line or "00:00 0" not in line: continue
                    if "/" in line or "\\" in line: continue
                    parts = line.split()
                    if not parts: continue
                    start_hex, end_hex = parts[0].split('-')
                    start = int(start_hex, 16)
                    end   = int(end_hex, 16)
                    size  = end - start
                    # Xbox RAM is usually exactly 64, 128, or 256 MB
                    if size in (0x04000000, 0x08000000, 0x10000000):
                        candidates.append((start, size))
        except: pass

        # Same selection as Windows: prefer a region that passes the
        # structural check, fall back to the largest. Keeping the two
        # platforms on one chooser means a fix to the heuristic cannot reach
        # only one of them, which is how the two page maps already drifted.
        best_addr, best = self._choose_ram_region(candidates)
        if best_addr is not None:
            self.xbox_ram_base = best_addr
            self.xbox_ram_size_mb = best // (1024 * 1024)
            return True
        return False

    # ---- Windows memory‑region search ------------------------------------
    def _find_xemu_base_windows(self):
        """
        Use CreateToolhelp32Snapshot + VirtualQueryEx to locate the
        emulated Xbox RAM region inside the Xemu process.
        """
        hSnap = ctypes.windll.kernel32.CreateToolhelp32Snapshot(
            TH32CS_SNAPPROCESS, 0)
        if hSnap == -1: return False

        pe = PROCESSENTRY32()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
        if ctypes.windll.kernel32.Process32First(hSnap, ctypes.byref(pe)):
            while True:
                if b"xemu.exe" in pe.szExeFile.lower():
                    self.pid = pe.th32ProcessID
                    break
                if not ctypes.windll.kernel32.Process32Next(hSnap, ctypes.byref(pe)):
                    break
        ctypes.windll.kernel32.CloseHandle(hSnap)
        if not self.pid: return False

        self.win_process_handle = ctypes.windll.kernel32.OpenProcess(
            PROCESS_ALL_ACCESS, False, self.pid)
        if not self.win_process_handle: return False

        cur = 0
        candidates = []
        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress",       ctypes.c_void_p),
                ("AllocationBase",    ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize",        ctypes.c_size_t),
                ("State",             wintypes.DWORD),
                ("Protect",           wintypes.DWORD),
                ("Type",              wintypes.DWORD),
            ]
        mbi = MEMORY_BASIC_INFORMATION()
        PAGE_GUARD = 0x100
        PAGE_EXECUTE_READWRITE = 0x40
        while ctypes.windll.kernel32.VirtualQueryEx(
                self.win_process_handle, ctypes.c_void_p(cur),
                ctypes.byref(mbi), ctypes.sizeof(mbi)):
            base = mbi.BaseAddress or 0
            if mbi.State == MEM_COMMIT and not (mbi.Protect & PAGE_GUARD) \
                    and (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)):
                # Every plausible region is collected, not just the biggest.
                # An exact == PAGE_READWRITE test used to miss a region that
                # merely had an extra flag set, and taking the largest match
                # blindly could land on a JIT cache instead of guest RAM.
                if mbi.RegionSize in (0x04000000, 0x08000000, 0x10000000):
                    candidates.append((base, mbi.RegionSize))
            # Advance from this region's own base: VirtualQueryEx rounds the
            # query address down to a page boundary, so RegionSize is measured
            # from BaseAddress and adding it to `cur` can skip or stall.
            nxt = base + mbi.RegionSize
            if nxt <= cur:
                break
            cur = nxt

        best_addr, best_size = self._choose_ram_region(candidates)
        if best_addr is not None:
            self.xbox_ram_base = best_addr
            self.xbox_ram_size_mb = best_size // (1024 * 1024)
            return True
        return False

    # ----------------------------------------------------------------------
    def _looks_like_xbox_ram(self, base, mem_file=None):
        """
        Confirm a candidate region really is the guest's RAM.

        Picking "the largest read-write region of a plausible size" is a guess.
        A host process can hold several regions that fit that description - a
        JIT code cache, GPU staging buffers - and choosing wrong means reading
        convincing-looking garbage forever.

        So check the structure instead. The Xbox page directory sits at guest
        physical 0xF000, and the XBE image is mapped at guest virtual 0x10000.
        Walk one PDE and one PTE, then look for the 'XBEH' magic at the
        physical address that falls out. Nothing but real Xbox RAM satisfies
        that chain, and it costs three small reads.

        Returns False when no title is loaded (the dashboard has no XBE at
        0x10000), so callers treat this as a preference, not a requirement.
        """
        def u32(off):
            raw = self.read_mem(base + off, 4, mem_file)
            if not raw or len(raw) != 4:
                return None
            return int.from_bytes(raw, 'little')

        try:
            va = 0x10000
            pde = u32(0xF000 + ((va >> 22) << 2))
            if not pde or not (pde & 1):
                return False
            if pde & 0x80:                       # 4 MB large page
                phys = (pde & 0xFFC00000) | (va & 0x3FFFFF)
            else:
                pte = u32((pde & 0xFFFFF000) + (((va >> 12) & 0x3FF) << 2))
                if not pte or not (pte & 1):
                    return False
                phys = (pte & 0xFFFFF000) | (va & 0xFFF)
            if phys is None or phys >= (self.xbox_ram_size_mb or 128) * 1024 * 1024:
                return False
            return self.read_mem(base + phys, 4, mem_file) == b'XBEH'
        except Exception:                                      # noqa: BLE001
            return False

    def _choose_ram_region(self, candidates):
        """
        Pick the guest RAM region from the candidates found by the OS scan.

        Prefers a region that passes the structural check. Falls back to the
        largest candidate so that attaching still works before a title is
        loaded, which is exactly when the structural check cannot pass.

        `candidates` is a list of (base_address, size_in_bytes).
        """
        if not candidates:
            return None, 0
        ranked = sorted(candidates, key=lambda c: -c[1])
        for addr, size in ranked:
            # size must be set before validating: _looks_like_xbox_ram bounds
            # the translated physical address against it.
            self.xbox_ram_size_mb = size // (1024 * 1024)
            if self._looks_like_xbox_ram(addr):
                self.ram_region_verified = True
                return addr, size
        self.ram_region_verified = False
        return ranked[0]

    # ----------------------------------------------------------------------
    def is_process_alive(self):
        """Check if the Xemu process is still running."""
        if self.pid is None:
            return False
        if self.os_type == "Linux":
            try:
                os.kill(self.pid, 0)
                with open(f"/proc/{self.pid}/comm", "r") as f:
                    if "xemu" not in f.read().lower():
                        return False
                return True
            except: return False
        else:
            if self.win_process_handle:
                code = wintypes.DWORD()
                if ctypes.windll.kernel32.GetExitCodeProcess(
                        self.win_process_handle, ctypes.byref(code)):
                    return code.value == 259  # STILL_ACTIVE
            return False

    def reconnect(self):
        """Try to find a new Xemu process if the old one died."""
        if self.os_type == "Windows" and self.win_process_handle:
            ctypes.windll.kernel32.CloseHandle(self.win_process_handle)
            self.win_process_handle = None
        self.pid = None
        self.xbox_ram_base = None
        self.xbox_ram_size_mb = 0
        return self.find_xemu_base()

    # ----------------------------------------------------------------------
    def read_mem(self, address, length, mem_file=None):
        """
        Read 'length' bytes from Xbox RAM.
        address : host virtual address (xbox_ram_base + offset)
        mem_file: Linux file handle for /proc/pid/mem (optional, for efficiency)
        """
        if self.os_type == "Linux":
            try:
                if mem_file is None:
                    # Callers may not have a handle (the page walker, the
                    # pointer dialog). Without this, seek() on None raised and
                    # the read silently returned zeros - which looked exactly
                    # like "this address contains 0".
                    mem_file = self._shared_mem_file()
                    if mem_file is None:
                        return b'\x00' * length
                mem_file.seek(address)
                return mem_file.read(length)
            except Exception:
                return b'\x00' * length
        elif self.os_type == "Windows":
            # ReadProcessMemory is all-or-nothing: if a single page anywhere
            # in the range is unreadable it fails and touches nothing. The old
            # code ignored both the BOOL return and bytes_read and handed back
            # the buffer regardless, so a failed read looked like a region full
            # of zeros - which during a full 128 MB dump means "scan found
            # nothing" with no error anywhere.
            buf = ctypes.create_string_buffer(length)
            got = ctypes.c_size_t(0)
            ok = ctypes.windll.kernel32.ReadProcessMemory(
                self.win_process_handle, ctypes.c_void_p(address),
                buf, length, ctypes.byref(got))
            if ok and got.value == length:
                return buf.raw[:length]
            # Retry page-aligned chunks so one bad page costs a page instead
            # of the whole request. Anything unreadable stays zero, matching
            # what the Linux path does with a short read.
            CHUNK = 0x10000
            out = bytearray(length)
            cbuf = ctypes.create_string_buffer(CHUNK)
            for off in range(0, length, CHUNK):
                n = min(CHUNK, length - off)
                g = ctypes.c_size_t(0)
                if ctypes.windll.kernel32.ReadProcessMemory(
                        self.win_process_handle,
                        ctypes.c_void_p(address + off), cbuf, n,
                        ctypes.byref(g)) and g.value:
                    out[off:off + g.value] = cbuf.raw[:g.value]
            return bytes(out)
        return b'\x00' * length

    def _shared_mem_file(self):
        """Lazily opened /proc/<pid>/mem handle for callers without one."""
        if not self.pid:
            return None
        fh = getattr(self, '_memfh', None)
        if fh is not None and getattr(self, '_memfh_pid', None) == self.pid:
            return fh
        try:
            fh = open(f"/proc/{self.pid}/mem", "r+b", buffering=0)
        except Exception:
            try:
                fh = open(f"/proc/{self.pid}/mem", "rb", buffering=0)
            except Exception:
                return None
        self._memfh = fh
        self._memfh_pid = self.pid
        return fh

    def write_mem(self, address, data, mem_file=None):
        """Write 'data' (bytes) to Xbox RAM."""
        if self.os_type == "Linux":
            try:
                if mem_file is None:
                    mem_file = self._shared_mem_file()
                    if mem_file is None:
                        return
                mem_file.seek(address)
                mem_file.write(data)
            except: pass
        elif self.os_type == "Windows":
            written = ctypes.c_size_t(0)
            if not ctypes.windll.kernel32.WriteProcessMemory(
                    self.win_process_handle, ctypes.c_void_p(address),
                    data, len(data), ctypes.byref(written)):
                # Guest RAM is committed read-write, so a failure here is
                # usually a protection change rather than a bad address.
                # Lift the protection for the write and put it straight back:
                # leaving a region writable that the emulator expected to be
                # read-only would be a worse bug than the failed write.
                PAGE_EXECUTE_READWRITE = 0x40
                old_prot = wintypes.DWORD(0)
                if ctypes.windll.kernel32.VirtualProtectEx(
                        self.win_process_handle, ctypes.c_void_p(address),
                        len(data), PAGE_EXECUTE_READWRITE,
                        ctypes.byref(old_prot)):
                    ctypes.windll.kernel32.WriteProcessMemory(
                        self.win_process_handle, ctypes.c_void_p(address),
                        data, len(data), ctypes.byref(written))
                    ctypes.windll.kernel32.VirtualProtectEx(
                        self.win_process_handle, ctypes.c_void_p(address),
                        len(data), old_prot, ctypes.byref(old_prot))

    # ---- Type helpers (for scanning/freezing) ----------------------------
    def _get_type_params(self, val_type, current_input=""):
        """Return (struct_format, size) for a given type string."""
        if "int8" in val_type:   return "B", 1
        if "int16" in val_type:  return "<H", 2
        if "int32" in val_type:  return "<I", 4
        if "float32" in val_type: return "<f", 4
        if "float64" in val_type: return "<d", 8
        if "String" in val_type:
            return "string", max(1, len(current_input))
        if "Array of Bytes" in val_type:
            clean = current_input.replace("??", "00").split()
            return "bytes", max(1, len(clean))
        return "B", 1

    # NEW: numpy dtype matching each numeric struct format, used by the
    # vectorized scan paths below. All little-endian to match the struct
    # formats used everywhere else in this file.
    _NP_DTYPE_FOR_FMT = None
    def _np_dtype_for_fmt(self, fmt):
        if not _HAVE_NUMPY:
            return None
        return {
            "B":  np.dtype("<u1"),
            "<H": np.dtype("<u2"),
            "<I": np.dtype("<u4"),
            "<f": np.dtype("<f4"),
            "<d": np.dtype("<f8"),
        }.get(fmt)

    def _parse_input_value(self, input_str, val_type):
        """Parse a user‑entered value into a Python object for scanning."""
        s = input_str.strip()
        if "String" in val_type: return s.encode('utf-8', 'ignore')
        if "Array of Bytes" in val_type: return s.lower()
        # Between mode (two numbers)
        if isinstance(s, tuple) or (isinstance(s, str) and " " in s):
            tokens = s.split() if isinstance(s, str) else s
            if len(tokens) >= 2:
                return (self._parse_single(tokens[0], val_type),
                        self._parse_single(tokens[1], val_type))
        return self._parse_single(s, val_type)

    def _parse_single(self, token, val_type):
        """Convert a single token to int or float, honoring hex prefix."""
        token = str(token).strip()
        is_hex = token.lower().startswith("0x") or \
                 any(c in token.lower() for c in 'abcdef')
        try:
            if "float32" in val_type or "float64" in val_type:
                if is_hex:
                    raw = bytes.fromhex(token.lower().replace("0x", ""))
                    fmt = '<f' if "float32" in val_type else '<d'
                    return struct.unpack(fmt, raw)[0]
                return float(token)
            base = 16 if (is_hex or token.lower().startswith("0x")) else 10
            return int(token, base)
        except: return 0

    def format_value(self, raw_bytes, val_type):
        """Format a raw byte string into a human‑readable value."""
        fmt, size = self._get_type_params(val_type, "")
        if len(raw_bytes) < size: return "?"
        try:
            if fmt == "string": return raw_bytes.decode('utf-8', 'ignore')
            if fmt == "bytes":  return raw_bytes.hex()
            return str(struct.unpack(fmt, raw_bytes)[0])
        except: return "?"

    # ---- Scan region restriction -----------------------------------------
    def set_scan_region(self, name, lo, hi, virtual=False):
        """
        Restrict subsequent scans to a region.

        Physical ranges are a contiguous span. Virtual ranges are NOT: their
        pages are scattered across physical RAM, so the region is expressed as a
        mask over physical pages built by walking the page tables. That mask is
        what makes "scan only the XBE image" or "scan only the user heap"
        possible at all - a physical lo/hi cannot describe those.
        """
        self.scan_region_name = name
        self.scan_virtual = bool(virtual)
        if lo is None:
            self.scan_pagemask = None
            self.scan_bytes = None
            return True
        total = self.xbox_ram_size_mb * 1024 * 1024
        npages = max(1, total // 0x1000)

        if not virtual:
            lo = max(0, min(lo, total))
            hi = max(lo, min(hi, total))
            mask = np.zeros(npages, dtype=bool)
            mask[lo >> 12:((hi + 0xFFF) >> 12)] = True
            self.scan_pagemask = mask
            self.scan_bytes = (lo, hi)      # exact bounds; the mask is coarse
            return True

        # Needs the full array; ensure_pagemap() may legitimately have
        # installed the on-demand walker, whose v2p is None.
        if self.ensure_pagemap_full() is None:
            return False
        v2p = self.pagemap.v2p
        vlo, vhi = lo >> 12, (hi + 0xFFF) >> 12
        pages = v2p[vlo:min(vhi, v2p.size)]
        pages = pages[pages != np.uint32(XboxPageMap.NONE)].astype(np.int64)
        pages = pages[pages < npages]
        mask = np.zeros(npages, dtype=bool)
        mask[pages] = True
        self.scan_pagemask = mask
        self.scan_bytes = None              # page granularity is exact enough here
        return bool(mask.any())

    def to_display_addr(self, off):
        """
        Physical offset -> the address space the user is scanning in.

        Scan results are physical offsets internally because that is how RAM is
        read. When the region selected is virtual, showing physical addresses is
        actively misleading: the user cannot paste them into a virtual code type
        or look them up in the viewer's Virtual mode.
        """
        if not self.scan_virtual or self.pagemap is None:
            return off
        v = self.pagemap.to_virt(off)
        return off if v is None else v

    def from_display_addr(self, addr):
        """Inverse of to_display_addr, for anything the user types back in."""
        if not self.scan_virtual or self.pagemap is None:
            return addr
        p = self.pagemap.to_phys(addr)
        return addr if p is None else p

    def _filter_offsets(self, offsets):
        """Drop candidate offsets outside the active scan region."""
        if self.scan_pagemask is None and self.scan_bytes is None:
            return offsets
        arr = np.asarray(offsets, dtype=np.int64)
        if arr.size == 0:
            return arr
        keep = np.ones(arr.size, dtype=bool)
        if self.scan_pagemask is not None:
            pg = arr >> 12
            keep &= (pg < self.scan_pagemask.size)
            keep[keep] &= self.scan_pagemask[pg[keep]]
        if self.scan_bytes is not None:
            lo, hi = self.scan_bytes
            keep &= (arr >= lo) & (arr < hi)
        return arr[keep]

    # ---- Scanning logic --------------------------------------------------
    def execute_first_scan_logic(self, target_value, val_type, is_unknown=False):
        """
        Perform a first scan on the entire Xbox RAM.
        Stores the full RAM dump and populates self.scan_results with
        matching offsets.
        """
        mem = None
        if self.os_type == "Linux":
            mem = open(f"/proc/{self.pid}/mem", "rb+", buffering=0)
        total = self.xbox_ram_size_mb * 1024 * 1024
        self.previous_snapshot = self.read_mem(self.xbox_ram_base, total, mem)
        if mem: mem.close()
        # Keep this dump around as the baseline for the *next* comparison scan.
        self._last_full_dump = self.previous_snapshot

        self.scan_results = []
        if is_unknown:
            _, size = self._get_type_params(val_type, "0")
            self._scan_item_size = size
            fmt, _ = self._get_type_params(val_type, "0")
            np_dtype = self._np_dtype_for_fmt(fmt)
            if np_dtype is not None:
                # Every aligned offset is a "candidate" for an unknown-value
                # search - build that list with numpy instead of a Python
                # range() -> list() (identical result, orders of magnitude
                # less memory/time for large RAM sizes).
                n_items = (total - size) // size + 1 if size else 0
                self.scan_results = self._filter_offsets(
                    np.arange(n_items, dtype=np.int64) * size).tolist()
            else:
                self.scan_results = self._filter_offsets(
                    list(range(0, total - size, size))).tolist()
            self.scan_values = {}
            return len(self.scan_results)

        parsed = self._parse_input_value(target_value, val_type)
        if "Array of Bytes" in val_type:
            tokens = parsed.split()
            pat = bytearray()
            for t in tokens:
                if t == '??': pat.append(0x2E)
                elif t == '2e': pat.extend(b'\x2E')
                else: pat.append(int(t, 16))
            self._scan_item_size = max(1, len(pat))
            for m in re.finditer(bytes(pat), self.previous_snapshot, re.DOTALL):
                self.scan_results.append(m.start())
            self.scan_results = self._filter_offsets(self.scan_results).tolist()
            self.scan_values = {}
            return len(self.scan_results)

        fmt, size = self._get_type_params(val_type, target_value)
        self._scan_item_size = size
        self.scan_values = {}

        # ---- Vectorized numeric first scan ---------------------------------
        np_dtype = self._np_dtype_for_fmt(fmt)
        if np_dtype is not None and fmt not in ("string", "bytes"):
            usable = (total // size) * size
            arr = np.frombuffer(self.previous_snapshot[:usable], dtype=np_dtype)
            if isinstance(parsed, tuple):
                lo, hi = parsed
                mask = (arr >= lo) & (arr <= hi)
            elif "float" in val_type:
                mask = np.abs(arr.astype(np.float64) - float(parsed)) < 0.001
            else:
                mask = (arr == parsed)
            idx = np.nonzero(mask)[0]
            offsets = self._filter_offsets(idx.astype(np.int64) * size)
            self.scan_results = offsets.tolist()
            self.scan_raw_prev = {}  # no longer used for numeric types; see execute_next_scan_logic
            for off in self.scan_results:
                self.scan_values[off] = self.format_value(
                    self.previous_snapshot[off:off+size], val_type)
            return len(self.scan_results)

        # ---- Fallback: pure-Python path (String type, or numpy unavailable) --
        for off in range(0, total - size,
                         1 if "String" in val_type else size):
            try:
                if fmt == "string":
                    if self.previous_snapshot[off:off+size] == parsed:
                        self.scan_results.append(off)
                else:
                    val, = struct.unpack_from(fmt, self.previous_snapshot, off)
                    if isinstance(parsed, tuple):
                        if parsed[0] <= val <= parsed[1]:
                            self.scan_results.append(off)
                    elif "float" in val_type:
                        if abs(val - parsed) < 0.001:
                            self.scan_results.append(off)
                    else:
                        if val == parsed:
                            self.scan_results.append(off)
            except: continue

        self.scan_results = self._filter_offsets(self.scan_results).tolist()
        self.scan_raw_prev = {}
        for off in self.scan_results:
            try:
                raw = self.previous_snapshot[off:off+size]
                self.scan_values[off] = self.format_value(raw, val_type)
                self.scan_raw_prev[off] = raw
            except: self.scan_values[off] = "?"
        return len(self.scan_results)

    def execute_next_scan_logic(self, target_value, val_type, scan_mode):
        """
        Filter self.scan_results down using the new memory state.

        THE BUG THAT WAS HERE: this used to (a) recompute the item size from
        whatever text happened to be sitting in the value box - which is
        often blank for modes like "Changed Value" / "Increased Value" -
        silently shrinking String/Array-of-Bytes comparisons to 1 byte, and
        (b) run a pure-Python per-offset loop THREE separate times over the
        *entire* previous result set (once to build the "previous value"
        display strings, once to filter, once more to re-read raw bytes for
        the next round). After an "Unknown Value Search" that previous
        result set is every aligned offset in RAM - tens of millions of
        entries for int8/int16 - so this wasn't actually broken, it was just
        functionally unusable: it would grind for minutes doing single-byte
        Python-level struct.unpack calls one at a time.
        """
        mem = None
        if self.os_type == "Linux":
            mem = open(f"/proc/{self.pid}/mem", "rb+", buffering=0)

        # Always use the size that was locked in for the CURRENT result set,
        # not one re-derived from a possibly-empty value box.
        fmt, fallback_size = self._get_type_params(val_type, target_value)
        size = self._scan_item_size if self._scan_item_size else fallback_size

        parsed = self._parse_input_value(target_value, val_type) \
            if scan_mode in ("Equal To", "Not Equal To", "Between",
                             "Increased Value By", "Decreased Value By") else 0

        np_dtype = self._np_dtype_for_fmt(fmt)
        use_vectorized = (_HAVE_NUMPY and np_dtype is not None and
                           fmt not in ("string", "bytes") and
                           self._last_full_dump is not None)

        if use_vectorized:
            total = self.xbox_ram_size_mb * 1024 * 1024
            new_dump = self.read_mem(self.xbox_ram_base, total, mem)
            if mem: mem.close()

            offsets_arr = np.array(self.scan_results, dtype=np.int64)
            if offsets_arr.size == 0:
                self.scan_results = []
                self.scan_values = {}
                self._last_full_dump = new_dump
                return 0

            old_buf = np.frombuffer(self._last_full_dump, dtype=np.uint8)
            new_buf = np.frombuffer(new_dump, dtype=np.uint8)

            # Gather each offset's raw bytes (N x size) and reinterpret as the
            # target numeric dtype in one shot - no per-offset Python loop.
            gather_idx = offsets_arr[:, None] + np.arange(size, dtype=np.int64)[None, :]
            old_vals = old_buf[gather_idx].copy().view(np_dtype).reshape(-1)
            new_vals = new_buf[gather_idx].copy().view(np_dtype).reshape(-1)

            old_f = old_vals.astype(np.float64)
            new_f = new_vals.astype(np.float64)
            is_float = "float" in val_type

            if scan_mode == "Equal To":
                mask = (np.abs(new_f - float(parsed)) < 0.001) if is_float else (new_vals == parsed)
            elif scan_mode == "Not Equal To":
                mask = (np.abs(new_f - float(parsed)) >= 0.001) if is_float else (new_vals != parsed)
            elif scan_mode == "Less Than":
                mask = new_vals < old_vals
            elif scan_mode == "Greater Than":
                mask = new_vals > old_vals
            elif scan_mode == "Between":
                lo, hi = parsed
                mask = (new_vals >= lo) & (new_vals <= hi)
            elif scan_mode == "Increased Value":
                mask = new_vals > old_vals
            elif scan_mode == "Decreased Value":
                mask = new_vals < old_vals
            elif scan_mode == "Increased Value By":
                mask = (np.abs((new_f - old_f) - float(parsed)) < 0.001) if is_float else \
                       ((new_vals - old_vals) == parsed)
            elif scan_mode == "Decreased Value By":
                mask = (np.abs((old_f - new_f) - float(parsed)) < 0.001) if is_float else \
                       ((old_vals - new_vals) == parsed)
            elif scan_mode == "Changed Value":
                mask = (np.abs(new_f - old_f) >= 0.001) if is_float else (new_vals != old_vals)
            elif scan_mode == "Unchanged Value":
                mask = (np.abs(new_f - old_f) < 0.001) if is_float else (new_vals == old_vals)
            else:
                mask = np.zeros(len(offsets_arr), dtype=bool)

            keep_idx = np.nonzero(mask)[0]
            filtered_offsets = offsets_arr[keep_idx]
            filtered_old_vals = old_vals[keep_idx]

            # Only format display strings for the offsets that actually
            # survive the filter, not the whole (potentially huge) input set.
            self.scan_values = {}
            for off, ov in zip(filtered_offsets.tolist(), filtered_old_vals.tolist()):
                if fmt == "<f" or fmt == "<d":
                    self.scan_values[off] = str(float(ov))
                else:
                    self.scan_values[off] = str(int(ov))

            self.scan_results = filtered_offsets.tolist()
            self.scan_raw_prev = {}          # unused in the vectorized path
            self._last_full_dump = new_dump  # becomes the baseline for the *next* Next Scan
            self.previous_snapshot = None
            return len(self.scan_results)

        # ---- Fallback: pure-Python path (String / Array of Bytes, or numpy
        #      unavailable). Same logic as before, but using the corrected
        #      'size' (see fix above) instead of one derived from a blank
        #      value box, so String/AOB comparison scans no longer silently
        #      truncate to 1 byte.
        filtered = []
        old_disp = {}
        use_snapshot = (not self.scan_raw_prev and self.previous_snapshot is not None)

        for off in self.scan_results:
            if use_snapshot:
                old_raw = self.previous_snapshot[off:off+size]
            else:
                old_raw = self.scan_raw_prev.get(off, b'')

            new_raw = self.read_mem(self.xbox_ram_base + off, size, mem)
            if fmt in ("string", "bytes"):
                old_val, new_val = old_raw, new_raw
            else:
                old_val = struct.unpack_from(fmt, old_raw, 0)[0] if len(old_raw) >= size else 0
                new_val = struct.unpack_from(fmt, new_raw, 0)[0] if len(new_raw) >= size else 0

            keep = False
            if scan_mode == "Equal To":
                keep = (new_val == parsed)
            elif scan_mode == "Not Equal To":
                keep = (new_val != parsed)
            elif scan_mode == "Less Than":
                keep = new_val < old_val
            elif scan_mode == "Greater Than":
                keep = new_val > old_val
            elif scan_mode == "Between":
                keep = isinstance(parsed, tuple) and parsed[0] <= new_val <= parsed[1]
            elif scan_mode == "Increased Value":
                keep = new_val > old_val
            elif scan_mode == "Decreased Value":
                keep = new_val < old_val
            elif scan_mode == "Increased Value By":
                keep = (new_val - old_val) == parsed if fmt != "bytes" else False
            elif scan_mode == "Decreased Value By":
                keep = (old_val - new_val) == parsed if fmt != "bytes" else False
            elif scan_mode == "Changed Value":
                keep = new_val != old_val
            elif scan_mode == "Unchanged Value":
                keep = new_val == old_val

            if keep:
                filtered.append(off)
                old_disp[off] = self.format_value(old_raw, val_type)

        new_raw_prev = {}
        for off in filtered:
            try:
                new_raw_prev[off] = self.read_mem(self.xbox_ram_base + off, size, mem)
            except:
                new_raw_prev[off] = b'\x00' * size
        self.scan_raw_prev = new_raw_prev
        self.previous_snapshot = None
        if mem: mem.close()
        self.scan_results = filtered
        self.scan_values = old_disp
        return len(self.scan_results)

    def reset_scan_engine(self):
        """Clear all scan state for a new search."""
        self.scan_results = []
        self.previous_snapshot = None
        self.scan_raw_prev = {}
        self._scan_item_size = None
        self._last_full_dump = None

    # ---- Freeze engine ---------------------------------------------------
    def pack_freeze_data(self, val_str, val_type):
        """Convert a value string into packed bytes for freezing."""
        fmt, _ = self._get_type_params(val_type, val_str)
        try:
            if fmt == "string": return val_str.encode('utf-8')
            if fmt == "bytes":  return bytes.fromhex(val_str.replace(" ", ""))
            if "float" in val_type: return struct.pack(fmt, float(val_str))
            is_hex = val_str.strip().lower().startswith("0x") or \
                     any(c in val_str.lower() for c in 'abcdef')
            return struct.pack(fmt, int(val_str, 16 if is_hex else 10))
        except: return None

    def start_trainer(self):
        """
        Start the freeze thread, retiring any previous one.

        _check_connection() calls this every time it (re)attaches, which is
        every 2 s while Xemu is closed. Without a generation counter each call
        stacked anotherever-running thread on top of the last - the log showed
        70+ live loop_trainer threads, all of them writing memory.
        """
        self._trainer_gen += 1
        gen = self._trainer_gen
        self.running = True
        threading.Thread(target=self.loop_trainer, args=(gen,),
                         daemon=True).start()

    def loop_trainer(self, gen=None):
        """
        Background thread that continuously writes frozen values.
        Handles both static addresses and pointer chains.
        """
        if self.pid is None:
            return
        mem = None
        if self.os_type == "Linux":
            try:
                mem = open(f"/proc/{self.pid}/mem", "rb+", buffering=0)
            except:
                self.running = False
                return
        try:
            while self.running and (gen is None or gen == self._trainer_gen):
                # reconnect() clears xbox_ram_base before re-scanning, so a
                # thread already inside this loop would compute None + offset.
                ram_base = self.xbox_ram_base   # NB: 'base' below is the
                if ram_base is None:            # entry's pointer base, not this
                    time.sleep(0.05)
                    continue
                for entry in self.address_table:
                    if len(entry) < 9: continue
                    (off, desc, vtype, frozen, lock_val, is_ptr,
                     base, offsets, static_off) = entry[:9]
                    if not frozen: continue
                    # Resolve pointer chain if this entry is a pointer
                    target = self.resolve_entry(entry, mem)
                    if target is None: continue
                    packed = self.pack_freeze_data(str(lock_val), vtype)
                    if packed:
                        self.write_mem(ram_base + target, packed, mem)
                time.sleep(0.01)
        finally:
            if mem: mem.close()

"""
Multi-level pointer scanner for Xbox (xemu) RAM dumps.

Design notes / why this replaces the old two-stage code:

  * The old Stage 1 accepted any dword < ram_size as a "pointer". On a 64 MB
    console that matches every small integer in RAM - counters, flags, floats
    with small exponents, packed ASCII. It then filtered by |ptr - target| <=
    0x4000000, which on a 64 MB console is the entire address space, i.e. a
    no-op. Result: millions of "nodes", none of them meaningful.

  * A real scanner does the opposite: it indexes *every* plausible pointer by
    what it points AT, then walks backwards from the target, one dereference
    at a time, keeping only paths that terminate inside the XBE image (the
    only region whose addresses are identical on every boot).

Address space facts this relies on:
  - Xbox user virtual addresses are identity-mapped to physical for the low
    region, so a RAM offset and a guest pointer value are numerically equal
    below 0x04000000.
  - 0x80000000 + off is the kernel's contiguous-physical window; D3D and
    MmAllocateContiguousMemory hand these out, so both forms must be accepted.
  - The XBE loads at a fixed base (header field, almost always 0x00010000)
    with a fixed image size. Static pointers live in there and only there.
"""
