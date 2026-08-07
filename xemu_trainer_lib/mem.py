"""Xemu process attach and raw RAM read/write.

Extracted verbatim from xemu_cheats_trainer.py.
"""
from .prelude import *  # noqa: F401,F403
import os, sys, time, struct, platform, threading, re, json, configparser
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog


class XemuMemory:
    """Minimal process handler for Xemu."""
    def __init__(self):
        self.pid = None
        self.xbox_ram_base = None
        self.xbox_ram_size_mb = 0
        self.os_type = platform.system()
        self.win_process_handle = None
        self.ram_region_verified = False
        # Everything below branches on Linux/Windows and falls through to a
        # no-op otherwise. On macOS that meant reads returned zeros and writes
        # vanished, with no error anywhere - the app looked attached and did
        # nothing. Name the condition so the UI can say so out loud.
        self.unsupported = self.os_type not in ("Linux", "Windows")

    SUPPORT_NOTE = (
        "Only Linux and Windows are supported.\n\n"
        "macOS needs task_for_pid() and the mach_vm_* API instead of "
        "/proc or ReadProcessMemory, which also means code signing and "
        "disabling SIP. That backend has not been written.")

    def find_xemu(self) -> bool:
        if self.os_type == "Linux":
            return self._find_linux()
        elif self.os_type == "Windows":
            return self._find_windows()
        return False

    def _find_linux(self) -> bool:
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
                    if size in (0x04000000, 0x08000000, 0x10000000):
                        candidates.append((start, size))
        except: pass
        best_addr, best = self._choose_ram_region(candidates)
        if best_addr is not None:
            self.xbox_ram_base = best_addr
            self.xbox_ram_size_mb = best // (1024 * 1024)
            return True
        return False

    def _find_windows(self) -> bool:
        hSnap = ctypes.windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
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
        self.win_process_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        if not self.win_process_handle: return False
        cur = 0
        candidates = []
        PAGE_GUARD = 0x100
        PAGE_EXECUTE_READWRITE = 0x40
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
        while ctypes.windll.kernel32.VirtualQueryEx(
                self.win_process_handle, ctypes.c_void_p(cur),
                ctypes.byref(mbi), ctypes.sizeof(mbi)):
            base = mbi.BaseAddress or 0
            # An exact == PAGE_READWRITE test misses a region carrying any
            # extra flag, and taking the largest match blindly can land on a
            # JIT cache rather than guest RAM. Collect every plausible region
            # and let _choose_ram_region verify which one is real.
            if mbi.State == MEM_COMMIT and not (mbi.Protect & PAGE_GUARD) \
                    and (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)):
                if mbi.RegionSize in (0x04000000, 0x08000000, 0x10000000):
                    candidates.append((base, mbi.RegionSize))
            # Advance from this region's base: VirtualQueryEx rounds the query
            # address down to a page boundary, so RegionSize is measured from
            # BaseAddress and adding it to `cur` can skip or stall.
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

    def _looks_like_xbox_ram(self, base, mem_file=None):
        """
        Confirm a candidate region really is the guest's RAM.

        "Largest read-write region of a plausible size" is a guess, and a host
        process can hold several regions matching it - a JIT cache, GPU
        staging buffers. Choosing wrong means reading convincing garbage.

        Check the structure instead: the Xbox page directory is at guest
        physical 0xF000 and the XBE is mapped at guest virtual 0x10000. Walk
        one PDE and one PTE and look for 'XBEH' at the physical address that
        falls out. Three small reads, and nothing else satisfies the chain.

        False when no title is loaded, so treat it as a preference.
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
            if pde & 0x80:
                phys = (pde & 0xFFC00000) | (va & 0x3FFFFF)
            else:
                pte = u32((pde & 0xFFFFF000) + (((va >> 12) & 0x3FF) << 2))
                if not pte or not (pte & 1):
                    return False
                phys = (pte & 0xFFFFF000) | (va & 0xFFF)
            if phys >= (self.xbox_ram_size_mb or 128) * 1024 * 1024:
                return False
            return self.read_mem(base + phys, 4, mem_file) == b'XBEH'
        except Exception:                                      # noqa: BLE001
            return False

    def _choose_ram_region(self, candidates):
        """
        Prefer a structurally verified region; fall back to the largest.

        The fallback matters: before a title is loaded there is no XBE at
        0x10000, and attaching at the dashboard must still work.
        """
        if not candidates:
            return None, 0
        ranked = sorted(candidates, key=lambda c: -c[1])
        for addr, size in ranked:
            self.xbox_ram_size_mb = size // (1024 * 1024)
            if self._looks_like_xbox_ram(addr):
                self.ram_region_verified = True
                return addr, size
        self.ram_region_verified = False
        return ranked[0]

    def is_alive(self) -> bool:
        if self.pid is None: return False
        if self.os_type == "Linux":
            try:
                os.kill(self.pid, 0)
                with open(f"/proc/{self.pid}/comm", "r") as f:
                    if "xemu" not in f.read().lower(): return False
                return True
            except: return False
        else:
            if self.win_process_handle:
                code = wintypes.DWORD()
                if ctypes.windll.kernel32.GetExitCodeProcess(self.win_process_handle, ctypes.byref(code)):
                    return code.value == 259
            return False

    def reconnect(self):
        if self.os_type == "Windows" and self.win_process_handle:
            ctypes.windll.kernel32.CloseHandle(self.win_process_handle)
            self.win_process_handle = None
        self.pid = None
        self.xbox_ram_base = None
        self.xbox_ram_size_mb = 0
        return self.find_xemu()

    def read_mem(self, address, length, mem_file=None):
        if self.os_type == "Linux":
            # os.pread() is one syscall; seek()+read() is two, and the freeze
            # loop runs this up to 1000x/sec per code line. pread is also
            # position-independent, so the GUI and the freeze thread can share
            # one handle without racing on the file offset.
            try:
                return os.pread(mem_file.fileno(), length, address)
            except Exception:
                try:
                    mem_file.seek(address)
                    return mem_file.read(length)
                except Exception:
                    return b'\x00' * length
        elif self.os_type == "Windows":
            # ReadProcessMemory is all-or-nothing: one unreadable page fails
            # the whole call. Ignoring the BOOL return and bytes_read made a
            # failed read indistinguishable from a region full of zeros.
            buf = ctypes.create_string_buffer(length)
            got = ctypes.c_size_t(0)
            ok = ctypes.windll.kernel32.ReadProcessMemory(
                self.win_process_handle, ctypes.c_void_p(address),
                buf, length, ctypes.byref(got))
            if ok and got.value == length:
                return buf.raw[:length]
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

    def write_mem(self, address, data, mem_file=None):
        if self.os_type == "Linux":
            try:
                os.pwrite(mem_file.fileno(), data, address)
            except Exception:
                try:
                    mem_file.seek(address)
                    mem_file.write(data)
                except Exception:
                    pass
        elif self.os_type == "Windows":
            written = ctypes.c_size_t(0)
            if not ctypes.windll.kernel32.WriteProcessMemory(
                    self.win_process_handle, ctypes.c_void_p(address),
                    data, len(data), ctypes.byref(written)):
                # Usually a protection change rather than a bad address. Lift
                # it for the write and restore it immediately - leaving a
                # region writable that the emulator expected to be read-only
                # would be worse than the failed write.
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

