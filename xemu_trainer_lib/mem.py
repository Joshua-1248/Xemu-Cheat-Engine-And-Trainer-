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
            self.pid = pid
            break
        if not self.pid: return False
        best = 0
        best_addr = None
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
                    if size in (0x04000000, 0x08000000, 0x10000000) and size > best:
                        best = size
                        best_addr = start
        except: pass
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
        best_size = 0
        best_addr = None
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
            if mbi.State == MEM_COMMIT and mbi.Protect == PAGE_READWRITE:
                if mbi.RegionSize in (0x04000000, 0x08000000, 0x10000000) and mbi.RegionSize > best_size:
                    best_size = mbi.RegionSize
                    best_addr = mbi.BaseAddress
            cur += mbi.RegionSize
        if best_addr is not None:
            self.xbox_ram_base = best_addr
            self.xbox_ram_size_mb = best_size // (1024 * 1024)
            return True
        return False

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
            buf = ctypes.create_string_buffer(length)
            bytes_read = ctypes.c_size_t(0)
            ctypes.windll.kernel32.ReadProcessMemory(
                self.win_process_handle, ctypes.c_void_p(address),
                buf, length, ctypes.byref(bytes_read))
            return buf.raw
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
            ctypes.windll.kernel32.WriteProcessMemory(
                self.win_process_handle, ctypes.c_void_p(address),
                data, len(data), None)

