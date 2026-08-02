"""Cheat code interpreter (all code types) and ASM patch journal.

Extracted verbatim from xemu_cheats_trainer.py.
"""
from .prelude import *  # noqa: F401,F403
import os, sys, time, struct, platform, threading, re, json, configparser
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from .cheat_tree import group_child, make_cheat  # noqa: F401
from .gdb_lite import GDB_HOST_DEFAULT, GDB_PORT_DEFAULT, GdbLite  # noqa: F401
from .mem import XemuMemory  # noqa: F401
from .pagemap import XboxPageMap  # noqa: F401


class CheatEngine:
    def __init__(self, mem: XemuMemory):
        self.pagemap = None          # XboxPageMap; rebuilt periodically
        self._pagemap_time = 0.0     # when it was last built
        self._pagemap_probe = None   # (virt, phys) sample used to detect staleness
        self.pagemap_ttl = 2.0       # seconds before a forced rebuild
        self.mem = mem
        self._increment_applied = {}
        self._maxb_mb = None      # cache for _off()
        self._maxb = 0
        # ---- [ASM] journal ----
        # A cheat whose name ends in [ASM] patches code rather than data, and
        # unlike a value write it does not undo itself when the freeze loop
        # stops rewriting it - the patched instruction just stays patched. So
        # the bytes that were there before the first write are kept here, keyed
        # by (block id, address space, address, size), and written back when the
        # cheat is switched off.
        #
        # Virtual-space entries are keyed by the VIRTUAL address and re-resolved
        # through the page map at restore time. Storing the physical address
        # would reintroduce the staleness bug: the guest rebuilds its page
        # tables on every level load, so the physical address a patch was
        # applied at may belong to something else entirely by the time it is
        # restored.
        self.asm_orig = {}
        self._asm_bid = 0
        self._asm_active = False
        # Code patches go through the gdbstub when one is listening, because a
        # raw /proc write leaves QEMU's JIT running the block it already
        # translated - the patch then does nothing until a save state or some
        # unrelated event invalidates it.
        self.gdb = None
        self.gdb_host = GDB_HOST_DEFAULT
        self.gdb_port = GDB_PORT_DEFAULT
        # ON by default. A /proc write to code is not merely slower - under
        # TCG it does nothing at all until something unrelated invalidates the
        # block, so an [ASM] patch silently fails. Connecting costs nothing
        # when no stub is listening (one refused connect every gdb_retry_secs)
        # and the raw write still runs as a fallback, so the only price of
        # leaving this on is that price. Turn it off in Settings if a game
        # misbehaves with the stub attached.
        self.gdb_enabled = True
        self.gdb_note = ""
        # Hold the socket open, or drop it the moment a patch is written?
        # xemu's stub takes ONE connection, so holding it locks the Cheat
        # Engine (and any real gdb) out for as long as the trainer is running.
        # [ASM] patches are one-shot - _asm_written stops them re-firing every
        # freeze tick - so there is nothing to keep the socket open for.
        self.gdb_hold = False
        self._gdb_last_ok = 0.0
        self._gdb_next_try = 0.0
        self.gdb_retry_secs = 3.0
        # (bid, space, addr) -> bytes we last wrote, so an [ASM] patch is
        # applied ONCE instead of on every freeze tick. Through the stub that
        # matters: each write costs a halt and a resume.
        self._asm_written = {}

    def parse_raw_code_text(self, text: str):
        """Parse a raw block of code lines into a list of (cmd, val) tuples."""
        lines = []
        for raw_line in text.strip().splitlines():
            line = raw_line.strip()
            if not line: continue
            parts = line.split()
            if len(parts) != 2: continue
            try:
                cmd = int(parts[0], 16)
                val = int(parts[1], 16)
                lines.append((cmd, val))
            except: pass
        return lines

    def parse_file(self, filepath: str):
        r"""
        Parse a .cht file into a cheat tree.

        A block name may carry a group path, Project 64 style:

            [Weapons\Ammo\Infinite Rockets] { ... }

        Backslash (or forward slash) separated components become nested groups,
        so a file can ship its own organisation. Names without a separator land
        at the top level exactly as before.

        Comment lines directly above a block carry metadata, the way Dolphin's
        Gecko list does:

            ; Author: Joshua
            ; Some notes about what this actually does
            [Weapons\Infinite Ammo] { ... }

        Anything after "Author:" becomes the author; other comment lines become
        the description. Blocks keep the order they appear in the file, which
        is what the "Order added" sort mode shows.
        """
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return self.parse_text(f.read())

    def parse_text(self, content: str):
        """Same grammar as parse_file, over a string - used by Paste Code."""
        root = []
        # [^\n] rather than . in the comment and name parts: DOTALL is needed
        # for the code body, and a greedy dot-all comment group swallows the
        # entire file.
        pattern = (r'((?:^[ \t]*;[^\n]*\n)*)'
                   r'\[([^\n]*)\]\s*\{\s*(.*?)\s*\}')
        for match in re.finditer(pattern, content, re.DOTALL | re.MULTILINE):
            author, notes = "", []
            for raw in match.group(1).splitlines():
                line = raw.strip().lstrip(';').strip()
                if not line:
                    continue
                low = line.lower()
                if low.startswith("author:"):
                    author = line.split(":", 1)[1].strip()
                elif low.startswith(("desc:", "description:")):
                    notes.append(line.split(":", 1)[1].strip())
                else:
                    notes.append(line)
            name = match.group(2).strip()
            body = re.sub(r'(?m)^\s*;.*?$', '', match.group(3)).strip()
            lines = self.parse_raw_code_text(body)
            if not lines:
                continue
            parts = [p.strip() for p in re.split(r'[\\/]', name) if p.strip()]
            if not parts:
                continue
            leaf = parts[-1]
            parent = root
            for comp in parts[:-1]:
                parent = group_child(parent, comp)
            parent.append(make_cheat(leaf, lines, desc=" ".join(notes),
                                     author=author))
        return root

    # ---------- memory helpers ----------
    def _off(self, addr):
        # maxb was recomputed on every call - two arithmetic ops per code line,
        # per pass, at up to 1 kHz. It only changes when the machine type does.
        mb = self.mem.xbox_ram_size_mb
        if mb != self._maxb_mb:
            self._maxb_mb = mb
            self._maxb = mb * 1024 * 1024
        maxb = self._maxb
        if 0x80000000 <= addr < 0x80000000 + maxb:
            return addr - 0x80000000
        if 0 <= addr < maxb:
            return addr
        return None

    def _r8(self, off, mem):
        raw = self.mem.read_mem(self.mem.xbox_ram_base + off, 1, mem)
        return raw[0] if len(raw) == 1 else None

    def _r16(self, off, mem):
        raw = self.mem.read_mem(self.mem.xbox_ram_base + off, 2, mem)
        return struct.unpack('<H', raw)[0] if len(raw) == 2 else None

    def _r32(self, off, mem):
        raw = self.mem.read_mem(self.mem.xbox_ram_base + off, 4, mem)
        return struct.unpack('<I', raw)[0] if len(raw) == 4 else None

    def _w8(self, off, val, mem):
        self.mem.write_mem(self.mem.xbox_ram_base + off, bytes([val & 0xFF]), mem)

    def _w16(self, off, val, mem):
        self.mem.write_mem(self.mem.xbox_ram_base + off, struct.pack('<H', val & 0xFFFF), mem)

    def _w32(self, off, val, mem):
        self.mem.write_mem(self.mem.xbox_ram_base + off, struct.pack('<I', val), mem)

    # ---- [ASM] journal ----------------------------------------------------
    ASM_SUFFIX = "[ASM]"

    @staticmethod
    def is_asm_name(name):
        """True for a cheat whose name ends in [ASM], case and space tolerant."""
        return str(name or "").strip().upper().endswith(CheatEngine.ASM_SUFFIX)

    def _asm_note(self, space, addr, size, mem_file=None):
        """
        Record the original bytes at a write target, once per patch site.

        Called before the write, and only while executing an [ASM] block. The
        `once` matters: the freeze loop reapplies an enabled cheat every tick,
        and re-reading on the second tick would capture the patch itself as the
        original, making restore a no-op that looks like it worked.
        """
        if not self._asm_active:
            return
        key = (self._asm_bid, space, addr, size)
        if key in self.asm_orig:
            return
        phys = addr if space == 'p' else self._asm_phys(addr, mem_file)
        if phys is None:
            return
        raw = self.mem.read_mem(self.mem.xbox_ram_base + phys, size, mem_file)
        if len(raw) == size:
            self.asm_orig[key] = bytes(raw)

    # ---- the stub ---------------------------------------------------------
    def gdb_connect(self, force=False):
        """
        Attach to xemu's gdbstub if one is listening. Never fatal.

        Tried once per session unless forced, so a game without `gdbserver`
        running does not pay a connection timeout on every tick.
        """
        if not self.gdb_enabled:
            return None
        if self.gdb is not None and self.gdb.alive:
            return self.gdb
        # Retry on a cooldown rather than giving up for the session. Trying
        # exactly once was a real bug: the first attempt happens the moment a
        # cheat is enabled, and if gdbserver was not running yet, starting it
        # afterwards changed nothing - the trainer never looked again, and
        # every patch kept going out through /proc where the JIT ignores it.
        now = time.time()
        if now < self._gdb_next_try and not force:
            return None
        self._gdb_next_try = now + self.gdb_retry_secs
        try:
            self.gdb = GdbLite(self.gdb_host, self.gdb_port).connect()
            self.gdb_note = "patching through xemu's gdbstub"
        except Exception as exc:                            # noqa: BLE001
            self.gdb = None
            self.gdb_note = (f"no gdbstub on {self.gdb_host}:{self.gdb_port} "
                             f"({exc}) - [ASM] patches may not take effect "
                             f"until a save state is loaded. In xemu's "
                             f"Monitor: gdbserver")
        return self.gdb

    def gdb_status(self):
        """
        (working, text) for the UI.

        With gdb_hold off the socket is normally closed, so "is it connected
        right now" would read as a failure between patches. What the user
        actually wants to know is whether the last patch went through the
        stub, so report that instead.
        """
        live = self.gdb is not None and self.gdb.alive
        recent = (time.time() - self._gdb_last_ok) < 30.0
        return (live or recent), self.gdb_note

    def gdb_close(self):
        self._gdb_next_try = 0.0
        if self.gdb is not None:
            try:
                self.gdb.detach()
            except Exception:                               # noqa: BLE001
                pass
        self.gdb = None
        self._gdb_tried = False

    def _asm_write(self, space, addr, data, mem_file=None):
        """
        Write an [ASM] patch, preferring the stub so the JIT drops its block.

        Falls back to the raw write whenever there is no stub or it refuses -
        the patch still lands, it just may not take effect until something
        invalidates the translation.
        """
        va = addr if space == 'v' else None
        if va is None:
            va = self._asm_virt(addr, mem_file)
        client = self.gdb_connect()
        if client is not None and client.alive and va is not None:
            halted = client.stop()
            try:
                if client.write_mem(va, data):
                    # Read it back over the SAME channel. A write the stub
                    # accepted but did not apply would otherwise look like a
                    # success and leave the JIT running the old code, which is
                    # the exact failure this route exists to prevent.
                    back = client.read_mem(va, len(data))
                    if back == data:
                        self.gdb_note = "patching through xemu's gdbstub"
                        self._gdb_last_ok = time.time()
                        return True
                    self.gdb_note = (f"the stub accepted the write at "
                                     f"0x{va:08X} but it read back as "
                                     f"{back.hex(' ') if back else '(nothing)'}")
            except Exception:                               # noqa: BLE001
                self.gdb = None
            finally:
                # Having interrupted, we owe a continue whatever happened.
                if halted:
                    client.cont()
                if not self.gdb_hold:
                    # Free the stub for the Cheat Engine / a real gdb. Clear
                    # the retry timer too, or the next patch would sit out the
                    # backoff meant for "no stub is listening".
                    self.gdb_close()
                    self._gdb_next_try = 0.0
        phys = addr if space == 'p' else self._asm_phys(addr, mem_file)
        if phys is None:
            return False
        self.mem.write_mem(self.mem.xbox_ram_base + phys, data, mem_file)
        return True

    def _asm_virt(self, phys, mem_file=None):
        if self.pagemap is None and self.refresh_pagemap(mem_file) is None:
            return None
        try:
            return self.pagemap.to_virt(phys)
        except Exception:                                   # noqa: BLE001
            return None

    def _asm_phys(self, va, mem_file=None):
        if self.pagemap is None:
            if self.refresh_pagemap(mem_file) is None:
                return None
        else:
            self.pagemap.mem_file = mem_file
        return self.pagemap.to_phys(va)

    def _asm_apply(self, space, addr, data, mem_file=None):
        """
        Apply an [ASM] patch once. Returns True if this handled the write.

        The freeze loop calls into here every tick; re-writing identical bytes
        through the stub would halt and resume the guest at the tick rate. So
        the write happens on the first tick, and afterwards only if the bytes
        on screen no longer match - which also re-applies a patch the game (or
        a level load) has overwritten.
        """
        if not self._asm_active:
            return False
        key = (self._asm_bid, space, addr)
        if self._asm_written.get(key) == data:
            phys = addr if space == 'p' else self._asm_phys(addr, mem_file)
            if phys is not None:
                cur = self.mem.read_mem(self.mem.xbox_ram_base + phys,
                                        len(data), mem_file)
                if cur == data:
                    return True             # already in place; nothing to do
        if self._asm_write(space, addr, data, mem_file):
            self._asm_written[key] = data
            return True
        return False

    def restore_asm(self, bid=None, mem_file=None):
        """
        Put the original bytes back for one [ASM] cheat, or for all of them.

        Returns (restored, failed). A failure means the address is no longer
        mapped - the title has unloaded or replaced that code - in which case
        the journal entry is dropped rather than retried forever, since there is
        nothing left to restore it into.
        """
        close_mem = False
        if mem_file is None and self.mem.os_type == 'Linux' and self.mem.pid:
            try:
                mem_file = open(f"/proc/{self.mem.pid}/mem", "rb+",
                                buffering=0)
                close_mem = True
            except OSError:
                mem_file = None
        restored = failed = 0
        try:
            for key in [k for k in self.asm_orig if bid is None or k[0] == bid]:
                _bid, space, addr, size = key
                orig = self.asm_orig[key]
                phys = addr if space == 'p' else self._asm_phys(addr, mem_file)
                if phys is None:
                    failed += 1
                    del self.asm_orig[key]
                    continue
                try:
                    # Same route as the patch, so the JIT drops the patched
                    # block and the original code runs again immediately.
                    self._asm_active = True
                    self._asm_bid = _bid
                    self._asm_write(space, addr, orig, mem_file)
                    self._asm_active = False
                    self._asm_written.pop((_bid, space, addr), None)
                    back = self.mem.read_mem(self.mem.xbox_ram_base + phys,
                                             size, mem_file)
                except Exception:                         # noqa: BLE001
                    back = b""
                if bytes(back) == orig:
                    restored += 1
                else:
                    failed += 1
                del self.asm_orig[key]
        finally:
            if close_mem and mem_file:
                mem_file.close()
        return restored, failed

    def asm_patch_count(self, bid=None):
        return sum(1 for k in self.asm_orig if bid is None or k[0] == bid)

    def clear_asm_journal(self):
        self._asm_written.clear()
        """
        Forget every recorded original without writing anything back.

        For when the journal cannot mean anything any more: a different title
        was launched, or xemu was restarted. Writing stale bytes into a fresh
        process would corrupt whatever now lives at those addresses.
        """
        self.asm_orig.clear()

    def execute_block(self, block, mem_file=None):
        codes = block['codes']
        exec_enabled = True
        idx = 0
        bid = block.get('_bid', 0)
        # Only [ASM] blocks journal their writes. Doing it for every cheat would
        # mean a read before every write in the freeze loop, at up to 1 kHz.
        self._asm_bid = bid
        self._asm_active = bool(block.get('_asm')) or \
            self.is_asm_name(block.get('name'))
        close_mem = False
        if mem_file is None and self.mem.os_type == 'Linux':
            try:
                mem_file = open(f"/proc/{self.mem.pid}/mem", "rb+", buffering=0)
                close_mem = True
            except: pass

        try:
            while idx < len(codes):
                cmd, val = codes[idx]
                code_type = (cmd >> 28) & 0xF
                offset = cmd & 0x0FFFFFFF

                if code_type == 0xC:
                    cur = self._r32(offset, mem_file)
                    exec_enabled = (cur is not None and cur == val)
                    idx += 1
                    continue

                if not exec_enabled:
                    if code_type == 0x3:
                        param = cmd & 0x0FFFFFFF
                        if param == 0x00400000 or param == 0x00500000:
                            idx += 2
                        else:
                            idx += 1
                    elif code_type == 0x7:
                        if idx + 1 < len(codes):
                            n = max(1, min(codes[idx + 1][0] & 0xFF, 8))
                            idx += 2 + max(0, n // 2)
                        else:
                            idx += 1
                    elif code_type in (0x4, 0x5, 0x6):
                        idx += 2
                    elif code_type in (0xD, 0xE):
                        n = self._d_n(cmd, val, code_type)
                        idx += 1 + n
                    else:
                        idx += 1
                    continue

                if code_type == 0x0:
                    self._asm_note('p', offset, 1, mem_file)
                    if not self._asm_apply('p', offset,
                                           bytes([val & 0xFF]), mem_file):
                        self._w8(offset, val & 0xFF, mem_file)
                    idx += 1
                elif code_type == 0x1:
                    self._asm_note('p', offset, 2, mem_file)
                    if not self._asm_apply('p', offset,
                                           struct.pack('<H', val & 0xFFFF),
                                           mem_file):
                        self._w16(offset, val & 0xFFFF, mem_file)
                    idx += 1
                elif code_type == 0x2:
                    self._asm_note('p', offset, 4, mem_file)
                    if not self._asm_apply('p', offset,
                                           struct.pack('<I', val), mem_file):
                        self._w32(offset, val, mem_file)
                    idx += 1
                elif code_type == 0x3:
                    idx = self._type3(codes, idx, offset, mem_file, bid)
                elif code_type == 0x4:
                    idx = self._type4(codes, idx, offset, val, mem_file)
                elif code_type == 0x5:
                    idx = self._type5(codes, idx, offset, val, mem_file)
                elif code_type == 0x6:
                    idx = self._type6(codes, idx, offset, val, mem_file)
                elif code_type == 0x7:
                    idx = self._type7(codes, idx, offset, val, mem_file)
                elif code_type == 0x8:
                    self._type89A(offset, 1, val, mem_file)
                    idx += 1
                elif code_type == 0x9:
                    self._type89A(offset, 2, val, mem_file)
                    idx += 1
                elif code_type == 0xA:
                    self._type89A(offset, 4, val, mem_file)
                    idx += 1
                elif code_type == 0xB:
                    idx = self._typeB(codes, idx, offset, val, mem_file)
                elif code_type == 0xF:
                    idx += 1          # hook code - reserved, not yet implemented
                elif code_type in (0xD, 0xE):
                    idx = self._typeD(codes, idx, cmd, val, code_type, mem_file)
                else:
                    idx += 1
        finally:
            self._asm_active = False
            if close_mem and mem_file:
                mem_file.close()

    def _d_n(self, cmd, val, code_type):
        if code_type == 0xD:
            return (val >> 24) & 0xFF
        else:
            return (cmd >> 16) & 0xFF

    def _type3(self, codes, idx, offset, mem_file, bid):
        if self._increment_applied.get(bid, False):
            cmd = codes[idx][0]
            param = cmd & 0x0FFFFFFF
            if param == 0x00400000 or param == 0x00500000:
                return idx + 2
            return idx + 1
        cmd, val = codes[idx]
        param = cmd & 0x0FFFFFFF
        addr = offset

        if (param & 0xFFFFFF00) == 0x00000000:
            cur = self._r8(addr, mem_file)
            if cur is not None:
                new = (cur + (param & 0xFF)) & 0xFF
                self._w8(addr, new, mem_file)
            self._increment_applied[bid] = True
            return idx + 1
        elif (param & 0xFFFFFF00) == 0x00100000:
            cur = self._r8(addr, mem_file)
            if cur is not None:
                new = (cur - (param & 0xFF)) & 0xFF
                self._w8(addr, new, mem_file)
            self._increment_applied[bid] = True
            return idx + 1
        elif (param & 0xFFFF0000) == 0x00200000:
            cur = self._r16(addr, mem_file)
            if cur is not None:
                new = (cur + (param & 0xFFFF)) & 0xFFFF
                self._w16(addr, new, mem_file)
            self._increment_applied[bid] = True
            return idx + 1
        elif (param & 0xFFFF0000) == 0x00300000:
            cur = self._r16(addr, mem_file)
            if cur is not None:
                new = (cur - (param & 0xFFFF)) & 0xFFFF
                self._w16(addr, new, mem_file)
            self._increment_applied[bid] = True
            return idx + 1
        elif param == 0x00400000:
            if idx + 1 >= len(codes): return idx + 1
            val_inc = codes[idx+1][1]
            cur = self._r32(addr, mem_file)
            if cur is not None:
                self._w32(addr, cur + val_inc, mem_file)
            self._increment_applied[bid] = True
            return idx + 2
        elif param == 0x00500000:
            if idx + 1 >= len(codes): return idx + 1
            val_dec = codes[idx+1][1]
            cur = self._r32(addr, mem_file)
            if cur is not None:
                self._w32(addr, cur - val_dec, mem_file)
            self._increment_applied[bid] = True
            return idx + 2
        return idx + 1

    def _type4(self, codes, idx, offset, val, mem_file):
        if idx + 1 >= len(codes): return idx + 1
        nnnn = (val >> 16) & 0xFFFF
        ssss = val & 0xFFFF
        next_cmd, next_val = codes[idx+1]
        v = next_cmd
        i = next_val
        addr = offset
        for _ in range(nnnn):
            self._w32(addr, v, mem_file)
            addr += ssss * 4
            v += i
        return idx + 2

    def _type5(self, codes, idx, src_off, length, mem_file):
        if idx + 1 >= len(codes): return idx + 1
        dest_off = codes[idx+1][0] & 0x0FFFFFFF
        data = self.mem.read_mem(self.mem.xbox_ram_base + src_off, length, mem_file)
        self.mem.write_mem(self.mem.xbox_ram_base + dest_off, data, mem_file)
        return idx + 2

    # ---- virtual addressing ------------------------------------------------
    def _pagemap_is_stale(self, mem_file=None):
        """
        Cheap check for whether the cached translation still holds.

        The page tables are rebuilt by the guest on every level load, so a map
        cached from a previous level silently resolves to the wrong physical
        address. Measured across real dumps, a stale map put the write 128 KB
        off target in 5 of 6 cross-level cases - it does not fail loudly, it
        just corrupts unrelated memory.

        Rather than rebuild the whole map every tick (expensive), re-read one
        page-directory entry and compare. If the guest has re-paged, it changes.
        """
        if self.pagemap is None:
            return True
        if time.time() - self._pagemap_time > self.pagemap_ttl:
            return True
        probe = self._pagemap_probe
        if probe is None:
            return True
        va, expect = probe
        try:
            raw = self.mem.read_mem(
                self.mem.xbox_ram_base + XboxPageMap.PD_PHYS + ((va >> 22) * 4),
                4, mem_file)
            if len(raw) < 4:
                return True
            return struct.unpack("<I", raw)[0] != expect
        except Exception:
            return True

    def refresh_pagemap(self, mem_file=None):
        """
        Build the on-demand translator.

        Deliberately NOT a full map: that read all 128 MB and took ~4 s, so with
        a periodic rebuild the freeze loop spent most of its time stalled and
        values visibly lagged. The walker reads 8 bytes per lookup instead.
        """
        try:
            pm = XboxPageMap.on_demand(self.mem, mem_file)
            self.pagemap = pm if pm.valid else None
            self._pagemap_time = time.time()
            self._pagemap_probe = None
            if self.pagemap is not None:
                self.pagemap.mem_file = mem_file
                # Remember the PDE covering the XBE image; it is the cheapest
                # thing to re-read to notice the guest has re-paged.
                va = 0x00010000
                pde_off = XboxPageMap.PD_PHYS + ((va >> 22) * 4)
                raw = self.mem.read_mem(self.mem.xbox_ram_base + pde_off, 4,
                                        mem_file)
                if len(raw) >= 4:
                    self._pagemap_probe = (va, struct.unpack("<I", raw)[0])
        except Exception:
            self.pagemap = None
        return self.pagemap

    def _rv32(self, va, mem_file):
        """Read a dword at a guest VIRTUAL address."""
        if self.pagemap is None:
            return None
        p = self.pagemap.to_phys(va)
        return None if p is None else self._r32(p, mem_file)

    def _type7(self, codes, idx, base_va, val, mem_file):
        """
        Type 0x7 - virtual pointer write, N dereferences.

            7aaaaaaa vvvvvvvv    a = 28-bit VIRTUAL base, v = value
            00SS00NN oooooooo    SS = size (00=8, 01=16, 02=32)
                                 NN = offset count (1-8)
                                 o  = offset 1
            oooooooo oooooooo    offsets 2..N, two per line

        Resolution is the standard convention:
            addr = [[[base] + o0] + o1] ... + o_last

        Line count is 2 + ceil((N-1)/2). Getting this wrong is not a silent
        no-op: a 3-offset chain parsed as 2 lines leaves the third line to be
        read as a fresh code, and `0000000C 000001E3` is a type-0 write of 0xE3
        to physical 0xC - inside the interrupt vector table. That is why a
        malformed chain freezes the console rather than doing nothing.
        """
        if idx + 1 >= len(codes):
            return idx + 1
        hdr, first_off = codes[idx + 1]
        size = (hdr >> 16) & 0xFF
        n = hdr & 0xFF
        if n < 1:
            n = 1
        n = min(n, 8)

        offs = [first_off]
        consumed = 2
        while len(offs) < n and idx + consumed < len(codes):
            w1, w2 = codes[idx + consumed]
            offs.append(w1)
            if len(offs) < n:
                offs.append(w2)
            consumed += 1
        # Always account for the declared line count, even if the block ended
        # early, so a truncated code cannot bleed into the next one.
        total_lines = 2 + max(0, (n - 1 + 1) // 2)

        if self._pagemap_is_stale(mem_file):
            if self.pagemap is not None:
                self.pagemap.invalidate()
        if self.pagemap is None and self.refresh_pagemap(mem_file) is None:
            return idx + total_lines
        self.pagemap.mem_file = mem_file

        cur = self._rv32(base_va, mem_file)
        if cur is None or cur == 0:
            return idx + total_lines
        for i, off in enumerate(offs):
            cur = (cur + off) & 0xFFFFFFFF
            if i == len(offs) - 1:
                break
            cur = self._rv32(cur, mem_file)
            if cur is None or cur == 0:
                return idx + total_lines

        target = self.pagemap.to_phys(cur)
        if target is None:
            return idx + total_lines
        if size == 0x00:
            self._w8(target, val & 0xFF, mem_file)
        elif size == 0x01:
            self._w16(target, val & 0xFFFF, mem_file)
        else:
            self._w32(target, val, mem_file)
        return idx + total_lines

    def _type89A(self, va, size, val, mem_file):
        """
        Types 0x8 / 0x9 / 0xA - constant write to a VIRTUAL address.

            8aaaaaaa 000000vv    8-bit
            9aaaaaaa 0000vvvv    16-bit
            Aaaaaaaa vvvvvvvv    32-bit

        The physical counterparts are types 0 / 1 / 2. Note the 28-bit address
        field cannot reach the 0x8xxxxxxx kernel window - but it does not need
        to, because that window is identity-mapped to physical, so types 0/1/2
        with the low 28 bits already address it.
        """
        if self.pagemap is None:
            if self.refresh_pagemap(mem_file) is None:
                return
        else:
            self.pagemap.mem_file = mem_file
            if self._pagemap_is_stale(mem_file):
                self.pagemap.invalidate()
        phys = self.pagemap.to_phys(va)
        if phys is None:
            return
        # Journalled against the virtual address, not this physical one.
        self._asm_note('v', va, size, mem_file)
        if self._asm_active:
            data = {1: bytes([val & 0xFF]),
                    2: struct.pack('<H', val & 0xFFFF),
                    4: struct.pack('<I', val)}.get(size)
            if data is not None and self._asm_apply('v', va, data, mem_file):
                return
        if size == 1:
            self._w8(phys, val & 0xFF, mem_file)
        elif size == 2:
            self._w16(phys, val & 0xFFFF, mem_file)
        else:
            self._w32(phys, val, mem_file)

    def _type6(self, codes, idx, base_off, val, mem_file):
        if idx + 1 >= len(codes): return idx + 1
        next_cmd, offset_val = codes[idx+1]
        sub = (next_cmd >> 16) & 0xFFFF
        final_offset = offset_val
        base_ptr = self._r32(base_off, mem_file)
        if base_ptr is None or base_ptr == 0:
            return idx + 2
        base_ram = self._off(base_ptr)
        if base_ram is None: return idx + 2
        target = base_ram + final_offset
        if sub == 0x0000:
            self._w8(target, val & 0xFF, mem_file)
        elif sub == 0x0001:
            self._w16(target, val & 0xFFFF, mem_file)
        elif sub == 0x0002:
            self._w32(target, val, mem_file)
        return idx + 2

    def _typeB(self, codes, idx, offset, val, mem_file):
        param = val & 0xFFFF0000
        if param == 0x00000000:
            cur = self._r8(offset, mem_file)
            if cur is not None: self._w8(offset, cur | (val & 0xFF), mem_file)
        elif param == 0x00100000:
            cur = self._r16(offset, mem_file)
            if cur is not None: self._w16(offset, cur | (val & 0xFFFF), mem_file)
        elif param == 0x00200000:
            cur = self._r8(offset, mem_file)
            if cur is not None: self._w8(offset, cur & (val & 0xFF), mem_file)
        elif param == 0x00300000:
            cur = self._r16(offset, mem_file)
            if cur is not None: self._w16(offset, cur & (val & 0xFFFF), mem_file)
        elif param == 0x00400000:
            cur = self._r8(offset, mem_file)
            if cur is not None: self._w8(offset, cur ^ (val & 0xFF), mem_file)
        elif param == 0x00500000:
            cur = self._r16(offset, mem_file)
            if cur is not None: self._w16(offset, cur ^ (val & 0xFFFF), mem_file)
        return idx + 1

    def _typeD(self, codes, idx, cmd, val, code_type, mem_file):
        n = self._d_n(cmd, val, code_type)
        if code_type == 0xD:
            offset = cmd & 0x0FFFFFFF
            compare_val = val & 0xFFFF
            test = (val >> 20) & 0x7
            is_8bit = ((val >> 19) & 1) == 1
        else:
            offset = val & 0x0FFFFFFF
            compare_val = cmd & 0xFFFF
            test = (val >> 28) & 0x7
            is_8bit = ((cmd >> 24) & 0xF) == 1
        if is_8bit:
            mem_val = self._r8(offset, mem_file)
        else:
            mem_val = self._r16(offset, mem_file)
        if mem_val is None:
            return idx + 1
        cond = False
        if test == 0: cond = mem_val == compare_val
        elif test == 1: cond = mem_val != compare_val
        elif test == 2: cond = mem_val < compare_val
        elif test == 3: cond = mem_val > compare_val
        elif test == 4: cond = not (mem_val & compare_val)
        elif test == 5: cond = (mem_val & compare_val) != 0
        elif test == 6: cond = (mem_val | compare_val) == 0
        elif test == 7: cond = (mem_val | compare_val) != 0
        if cond:
            return idx + 1
        else:
            return idx + 1 + n

    def apply_all(self, blocks, mem_file=None):
        for blk in blocks:
            if blk.get('enabled', False):
                self.execute_block(blk, mem_file)
                
