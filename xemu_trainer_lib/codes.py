"""Cheat code interpreter (all code types) and ASM patch journal.

Originally extracted verbatim from xemu_cheats_trainer.py; the code type table
has since been revised.

CODE TYPE MAP
-------------
The type is the top nibble of the first word.

    0   8-bit constant write
    1   16-bit constant write
    2   32-bit constant write
    3   Increment / Decrement
    4   32-bit constant serial write
    5   Copy bytes
    6   Pointer write - physical OR virtual, selected by a flag byte
    7   UNUSED  (was: pointer write, virtual)  <- free
    8   8-bit constant write   (virtual)
    9   16-bit constant write  (virtual)
    A   32-bit constant write  (virtual)
    B   Boolean operation
    C   32-bit "do all following codes if equal to"
    D   Do multi-lines if conditional (physical OR virtual compare address,
        selected by a flag bit - see _d_addr_space)
    E   Conditional ON/OFF switch (button toggle) - same fields as D
    F   Hook code - reserved, not implemented

Two types were retired rather than kept as near-duplicates:

  * 7 folded into 6. The two differed only in which address space the base and
    intermediate pointers live in, which is a flag, not a code type. Type 6's
    header byte now carries it: 00 physical, 01 virtual.

  * E's old meaning folded into D. Verified field by field across 200,000
    random codes - the 28-bit offset, 16-bit compare, 3-bit test, 8/16-bit
    selector and 8-bit line count are all expressible in D. Only the bit layout
    differed. The conversion is documented on _typeD.

E has since been REASSIGNED to an on/off switch, modelled on Gecko's CC code.
It reuses D's field layout exactly, so a D code becomes a toggle by changing
one nibble. The difference is that E treats the condition as an EDGE: the
switch flips on a false -> true transition and the guarded lines run while it
is on, whether or not the condition still holds. That is what makes a button
press a toggle rather than a hold. See _typeE.

Anything still using the OLD type E semantics must be converted to D first;
those codes will now behave as switches, which is not what they meant.

Both retired types are still CONSUMED with their old line counts rather than
skipped as one line. An unhandled multi-line code leaves its tail to be read as
fresh codes, and `0000000C 000001E3` is a type-0 write of 0xE3 to physical 0xC,
inside the interrupt vector table. A retired conditional additionally skips the
lines it guarded, so an old cheat stops working rather than applying writes its
author had gated behind a check.

7 remains free. When it is assigned, replace the reserved branch in
execute_block with the new handler and update this table.
"""
from .prelude import *  # noqa: F401,F403
import os, sys, time, struct, platform, threading, re, json, configparser
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from . import cheatfiles
from .cheat_tree import group_child, make_cheat  # noqa: F401
from .gdb_lite import GDB_HOST_DEFAULT, GDB_PORT_DEFAULT, GdbLite  # noqa: F401
from .online_guard import OnlineGuard  # noqa: F401
from .mem import XemuMemory  # noqa: F401
from .pagemap import XboxPageMap  # noqa: F401


class CheatEngine:
    # How long an [ASM] patch is trusted from its journal before the bytes
    # are read back again. Long enough that toggling other cheats costs
    # nothing, short enough to notice a level load overwriting a patch.
    ASM_VERIFY_INTERVAL = 5.0

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
        # Cheats are held while xemu is in an online match. See
        # online_guard.py for what is detected and what it cannot catch.
        # Whitelist lives beside the cheats/ and patches/ folders.
        # One socket, two callers: the freeze thread applies enabled cheats
        # continuously while the UI applies them again on every toggle. Without
        # mutual exclusion their packets interleave on the same connection, the
        # protocol desyncs, reads time out, and the guest is left halted.
        self._gdb_lock = threading.RLock()
        self._gdb_guest_stopped = False
        self.online_guard = OnlineGuard()
        # Writes queued by an [ASM] block, flushed as merged runs when the
        # block ends. One `M` packet per contiguous run instead of one per
        # code line - a 19-line cave patch is two packets, not nineteen.
        self._asm_defer = False
        self._asm_pending = []
        self.online_titleid = ""      # set by the UI when a game is selected
        self.online_blocked_names = set()   # reported to the UI once per pass
        self.online_block_reason = ""
        self.gdb_hold = False
        self._gdb_last_ok = 0.0
        self._gdb_next_try = 0.0
        self.gdb_retry_secs = 3.0
        # (bid, space, addr) -> bytes we last wrote, so an [ASM] patch is
        # applied ONCE instead of on every freeze tick. Through the stub that
        # matters: each write costs a halt and a resume.
        self._asm_written = {}
        self._asm_verified = {}   # key -> last time bytes confirmed
        # Type E on/off switches. Keyed (bid, line index) so two switches in
        # one cheat stay independent, and so a switch keeps its state across
        # freeze ticks - which is the whole point of it.
        self._switches = {}

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

            [Weapons\Ammo\Infinite Rockets]
            author=Joshua
            desc=Some notes about what this actually does
            00000001 00000002

        Backslash (or forward slash) separated components become nested groups,
        so a file can ship its own organisation. Names without a separator land
        at the top level exactly as before.

        A bracketed name opens a block; the next one, a `//` directive, or
        end of file closes it. There is no closing delimiter:

            [Weapons\Infinite Ammo]
            author=Joshua
            00000001 00000002

        The older brace form, with `; Author:` lines above a `[Name] { ... }`
        block, is still read, so blocks copied from older files and from forum
        posts keep pasting. Blocks keep the order they appear in the file,
        which is what the "Order added" sort mode shows.
        """
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return self.parse_text(f.read())

    def parse_text(self, content: str):
        """
        Same grammar as parse_file, over a string - used by Paste Code.

        Delegates to cheatfiles.parse_pasted_text so the clipboard and the
        on-disk files can never drift into speaking different dialects. Both
        the current brace-free form and the older `[Name] { ... }` form parse.
        """
        return cheatfiles.parse_pasted_text(content)

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
        with self._gdb_lock:
            self._gdb_close_locked()

    def _gdb_close_locked(self):
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
            # Serialise the whole halt-write-verify-resume sequence. Anything
            # less and the freeze thread can interleave a packet between our
            # stop and our continue, which desyncs the protocol and strands the
            # guest.
            self._gdb_lock.acquire()
            halted = False
            try:
                # stop() inside the try, so an exception here still reaches the
                # finally and releases the lock. Holding it after a failure
                # would wedge the freeze thread as well.
                #
                # Skipped when a batched block already halted the guest: a
                # second 0x03 while stopped is at best noise on the wire, and
                # `halted` staying False keeps us from owing a second resume.
                if not self._gdb_guest_stopped:
                    halted = client.stop()
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
                # Deliberately NOT clearing self.gdb here. The finally below
                # has to detach, and gdb_close() only acts when self.gdb is
                # still set - clearing it first turned the detach into a no-op
                # and left xemu paused with no way back.
                self.gdb_note = "gdbstub error; fell back to a raw write"
            finally:
                # Order here is load-bearing, and getting it wrong leaves xemu
                # paused after every toggle.
                #
                # QEMU's gdb_read_byte does this:
                #
                #     if (runstate_is_running()) {
                #         /* when the CPU is running, we cannot do anything
                #            except stop it when receiving a char */
                #         vm_stop(RUN_STATE_PAUSED);
                #     }
                #
                # So ANY byte that arrives while the guest is running re-pauses
                # it and is then discarded. Sending "c" and then "D" therefore
                # resumes the guest and immediately stops it again, and the
                # socket closes with xemu paused and nothing left to resume it.
                #
                # "D" on its own both detaches and resumes, so when we are
                # letting the connection go it must be sent INSTEAD of the
                # continue, while the guest is still stopped.
                if not self.gdb_hold:
                    # Detach the client we actually used, rather than going
                    # through self.gdb - an error above may have replaced or
                    # cleared it, and the resume must happen regardless.
                    try:
                        client.detach()
                    except Exception:                       # noqa: BLE001
                        pass
                    self.gdb = None
                    self._gdb_tried = False
                    self._gdb_next_try = 0.0
                elif halted:
                    # Batching (gdb_hold): deliberately DO NOT continue here.
                    #
                    # Resuming after each line would mean the next line's stop
                    # byte, and finally the block's detach, all arrive while the
                    # guest is running - and QEMU re-pauses on any byte received
                    # while running, then discards it. That is the same trap as
                    # above, just spread across a block: the last thing sent
                    # would be a "D" that pauses instead of resuming.
                    #
                    # So the guest stays halted for the whole block and is
                    # resumed exactly once, by the detach in execute_block's
                    # finally. Marked here so that resume is unconditional.
                    self._gdb_guest_stopped = True
                self._gdb_lock.release()
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
            # Trust the journal for a short while before re-verifying.
            #
            # Verification reads back through _asm_phys, a physical translation
            # separate from the virtual address the patch was written to. When
            # the page map is cold or has been rebuilt, that read can miss and
            # the patch looks absent - so the code re-applied it, which meant
            # halting the guest through the stub. That is why toggling an
            # unrelated, non-[ASM] cheat paused the emulator once: the toggle
            # re-runs every enabled block, and the first verification after a
            # rebuild failed.
            #
            # The periodic re-check still exists, because a level load really
            # can overwrite a patch. It just does not run on every pass.
            last = self._asm_verified.get(key, 0.0)
            if (time.time() - last) < self.ASM_VERIFY_INTERVAL:
                return True                 # journalled recently; nothing to do
            phys = addr if space == 'p' else self._asm_phys(addr, mem_file)
            if phys is not None:
                cur = self.mem.read_mem(self.mem.xbox_ram_base + phys,
                                        len(data), mem_file)
                if cur == data:
                    self._asm_verified[key] = time.time()
                    return True             # already in place; nothing to do
                # A mismatch here may be a stale translation rather than a lost
                # patch. Re-resolve once and look again before paying for a
                # stub round trip.
                self.refresh_pagemap(mem_file)
                phys2 = addr if space == 'p' else self._asm_phys(addr, mem_file)
                if phys2 is not None and phys2 != phys:
                    cur = self.mem.read_mem(self.mem.xbox_ram_base + phys2,
                                            len(data), mem_file)
                    if cur == data:
                        self._asm_verified[key] = time.time()
                        return True
        if self._asm_defer:
            # Everything above has already decided this site genuinely needs
            # writing. Queue it and claim the write so execute_block does not
            # fall through to its raw-write path; the flush owns the outcome,
            # including falling back to a raw write if the stub refuses.
            self._asm_pending.append((key, space, addr, data))
            return True
        if self._asm_write(space, addr, data, mem_file):
            self._asm_written[key] = data
            self._asm_verified[key] = time.time()
            return True
        return False

    # 4 KiB, because a physical run that crosses a page boundary is not
    # contiguous in virtual space, and _asm_write resolves the run by its
    # first address. Applied to virtual runs too - harmless there, and it
    # keeps one rule instead of two.
    ASM_MERGE_LIMIT = 0x1000

    @staticmethod
    def _asm_runs(entries):
        """
        Merge queued writes into maximal contiguous runs.

        Bytes are splatted into a sparse map first, so two codes touching the
        same address resolve last-write-wins in queue order - the same result
        applying them one at a time would give. Runs never span a page.

        Returns [(space, start, data, [keys...])].
        """
        by_space = {}
        for key, space, addr, data in entries:
            m, owners = by_space.setdefault(space, ({}, {}))
            for i, b in enumerate(data):
                m[addr + i] = b
                owners[addr + i] = key
        out = []
        for space, (m, owners) in by_space.items():
            start = prev = None
            buf, keys = bytearray(), []
            for a in sorted(m):
                if (start is not None and a == prev + 1
                        and (a // CheatEngine.ASM_MERGE_LIMIT
                             == start // CheatEngine.ASM_MERGE_LIMIT)):
                    buf.append(m[a])
                else:
                    if start is not None:
                        out.append((space, start, bytes(buf), keys))
                    start, buf, keys = a, bytearray([m[a]]), []
                if owners[a] not in keys:
                    keys.append(owners[a])
                prev = a
            if start is not None:
                out.append((space, start, bytes(buf), keys))
        return out

    def _asm_flush(self, mem_file=None):
        """
        Write everything an [ASM] block queued, as merged runs.

        Called from execute_block's finally, while the guest is still halted
        and the stub connection still held, so the whole block lands inside one
        stop/resume. A run the stub refuses falls back to a raw write, which is
        what the per-line path did before deferral existed.
        """
        entries, self._asm_pending = self._asm_pending, []
        if not entries:
            return
        sizes = {}
        for key, space, addr, data in entries:
            sizes[key] = (space, addr, data)
        for space, start, data, keys in self._asm_runs(entries):
            ok = self._asm_write(space, start, data, mem_file)
            if not ok:
                # The run did not go through the stub. Land the bytes anyway so
                # behaviour matches the old path; the patch may not take effect
                # until something invalidates the translation, and gdb_note
                # already says so.
                phys = start if space == 'p' else self._asm_phys(start, mem_file)
                if phys is not None:
                    self.mem.write_mem(self.mem.xbox_ram_base + phys,
                                       data, mem_file)
            now = time.time()
            for key in keys:
                # Journal against the original per-code key and its own bytes,
                # not the merged run, so restore_asm and the verify path are
                # unchanged by merging.
                _, _, kdata = sizes[key]
                self._asm_written[key] = kdata
                self._asm_verified[key] = now

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
        """
        Forget every recorded original without writing anything back.

        For when the journal cannot mean anything any more: a different title
        was launched, or xemu was restarted. Writing stale bytes into a fresh
        process would corrupt whatever now lives at those addresses.

        Switch states go with it, for the same reason - a type E switch left on
        would apply its guarded lines the instant the next game attached, with
        no button pressed and nothing on screen to explain it.
        """
        self._asm_written.clear()
        self._asm_pending = []
        self._asm_defer = False
        self._asm_verified.clear()
        self.asm_orig.clear()
        self.clear_switches()

    def execute_block(self, block, mem_file=None):
        # Refuse while xemu is in an online match. Checked here, at the single
        # point every cheat write funnels through, rather than in the UI - a
        # gate in the UI only stops the button, not the freeze thread that
        # keeps re-applying an already-enabled cheat.
        name = block.get('name')
        blocked, why = self.online_guard.blocked(
            self.mem.pid, name, block.get('codes'), self.online_titleid)
        if blocked:
            self.online_blocked_names.add(str(name or "?"))
            self.online_block_reason = why
            return
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

        # Hold the stub connection open for the whole block. Without this each
        # [ASM] line connects, halts, writes, detaches and resumes on its own,
        # so a four-line patch stutters the emulator four times. Released in
        # the finally below, which also resumes the guest.
        outer_hold = self.gdb_hold
        if self._asm_active:
            self.gdb_hold = True
            # Only the outermost block defers, so a nested call cannot flush a
            # queue its caller is still filling.
            if not outer_hold:
                self._asm_defer = True
                self._asm_pending = []

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
                    elif code_type == 0x6:
                        # Type 6 is 2 + N//2 lines, not a fixed 2. Skipping a
                        # fixed 2 while a conditional is false would leave the
                        # offset lines of a multi-level chain to be read as
                        # fresh codes - and `0000000C 000001E3` is a type-0
                        # write into the interrupt vector table.
                        if idx + 1 < len(codes):
                            n = max(1, min(codes[idx + 1][0] & 0xFF, 8))
                            idx += 2 + (n // 2)
                        else:
                            idx += 1
                    elif code_type == 0x7:
                        # Reserved; same line count as the retired handler so
                        # the two paths cannot disagree about how far to skip.
                        if idx + 1 < len(codes):
                            n = max(1, min(codes[idx + 1][0] & 0xFF, 8))
                            idx += 2 + (n // 2)
                        else:
                            idx += 1
                    elif code_type in (0x4, 0x5):
                        idx += 2
                    elif code_type in (0xD, 0xE):
                        # E is retired but still consumes its guarded lines
                        # here, so the two paths agree on how far to skip.
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
                    # RESERVED - formerly the virtual pointer write, now folded
                    # into type 6 with a space flag.
                    #
                    # Consumed rather than ignored. Falling through to the
                    # default `idx += 1` would leave an old code's header line
                    # to be read as a fresh code, and `00020002 0000021C` is a
                    # type-0 write of 0x1C to physical 0x20002. Doing nothing
                    # is the intended behaviour; doing nothing *quietly* is not
                    # the same as skipping one line.
                    #
                    # When 7 is reassigned, replace this with the new handler.
                    if idx + 1 < len(codes):
                        n = max(1, min(codes[idx + 1][0] & 0xFF, 8))
                        idx += 2 + (n // 2)
                    else:
                        idx += 1
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
                elif code_type == 0xD:
                    idx = self._typeD(codes, idx, cmd, val, code_type, mem_file)
                elif code_type == 0xE:
                    idx = self._typeE(codes, idx, cmd, val, mem_file, bid)
                else:
                    idx += 1
        finally:
            self._asm_active = False
            # Release the held connection. gdb_close sends "D", which both
            # detaches and resumes, so this is what un-pauses the guest after
            # a multi-line patch.
            if self._asm_defer and not outer_hold:
                # Before the hold is released: the flush needs the guest still
                # halted and the connection still open.
                self._asm_defer = False
                try:
                    self._asm_flush(mem_file)
                except Exception:                           # noqa: BLE001
                    self._asm_pending = []
            if self.gdb_hold and not outer_hold:
                self.gdb_hold = False
                # The guest has been held stopped for the whole block. "D"
                # detaches and resumes in one go, and must be the only thing
                # sent - a continue first would leave the detach arriving while
                # running, which pauses again.
                self.gdb_close()
                self._gdb_guest_stopped = False
                self._gdb_next_try = 0.0
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

    def _type6(self, codes, idx, base, val, mem_file):
        """
        Type 0x6 - pointer write, N dereferences, physical OR virtual base.

            6aaaaaaa vvvvvvvv    a = 28-bit base address, v = value
            XXSS00NN oooooooo    XX = 00 physical base, 01 virtual base
                                 SS = size (00=8, 01=16, 02=32)
                                 NN = offset count (1-8)
                                 o  = offset 1
            oooooooo oooooooo    offsets 2..N, two per line

        Resolution is the standard convention:
            addr = [[[base] + o0] + o1] ... + o_last

        XX replaces what used to be a whole separate code type. Type 7 was the
        virtual-base version of exactly this, differing only in which address
        space the base and the intermediate pointers live in - a flag byte
        expresses that far better than burning a type on it.

        This parse is backward compatible with the old type 6, which wrote
        `00SS0000 oooooooo`: XX reads as 00 (physical) and NN as 0, which
        clamps to a single offset. That is precisely what the old handler did,
        so existing type 6 codes keep working untouched.

        Line count is 2 + N//2. Getting it wrong is not a silent no-op: a
        3-offset chain parsed as 2 lines leaves the third line to be read as a
        fresh code, and `0000000C 000001E3` is a type-0 write of 0xE3 to
        physical 0xC - inside the interrupt vector table.
        """
        if idx + 1 >= len(codes):
            return idx + 1
        hdr, first_off = codes[idx + 1]
        virtual = ((hdr >> 24) & 0xFF) == 0x01
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
        total_lines = 2 + (n // 2)

        target = (self._resolve_virtual_chain(base, offs, mem_file) if virtual
                  else self._resolve_physical_chain(base, offs, mem_file))
        if target is None:
            return idx + total_lines

        if size == 0x00:
            self._w8(target, val & 0xFF, mem_file)
        elif size == 0x01:
            self._w16(target, val & 0xFFFF, mem_file)
        else:
            self._w32(target, val, mem_file)
        return idx + total_lines

    def _resolve_physical_chain(self, base_off, offs, mem_file):
        """
        Walk a pointer chain whose base is a PHYSICAL offset.

        The base itself is physical, but every pointer stored in guest memory
        is a guest VIRTUAL address, so each dereference has to go back through
        the page map. That asymmetry is why the two chain walkers stay separate
        rather than being folded together with a flag.
        """
        cur = self._r32(base_off, mem_file)
        if cur is None or cur == 0:
            return None
        for i, off in enumerate(offs):
            ram = self._off(cur)
            if ram is None:
                return None
            target = ram + off
            if i == len(offs) - 1:
                return target
            cur = self._r32(target, mem_file)
            if cur is None or cur == 0:
                return None
        return None

    def _resolve_virtual_chain(self, base_va, offs, mem_file):
        """
        Walk a pointer chain whose base is a guest VIRTUAL address.

        Needs a current page map: a stale one lands writes far from the target
        rather than failing, so staleness is checked before the walk instead of
        after something has already been written.
        """
        if self._pagemap_is_stale(mem_file):
            if self.pagemap is not None:
                self.pagemap.invalidate()
        if self.pagemap is None and self.refresh_pagemap(mem_file) is None:
            return None
        self.pagemap.mem_file = mem_file

        cur = self._rv32(base_va, mem_file)
        if cur is None or cur == 0:
            return None
        for i, off in enumerate(offs):
            cur = (cur + off) & 0xFFFFFFFF
            if i == len(offs) - 1:
                break
            cur = self._rv32(cur, mem_file)
            if cur is None or cur == 0:
                return None
        return self.pagemap.to_phys(cur)

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

    def _d_addr_space(self, val):
        """
        Decode the type D/E size + address-space field.

        It is the WHOLE nibble at bits 16-19 - hex digit 3 of the value word,
        counting from the left. It reads as the literal digit:

            0 = 16-bit compare, physical
            1 = 16-bit compare, virtual
            2 = 8-bit compare,  physical
            3 = 8-bit compare,  virtual

        So in `NNTavvvv`, `a` is exactly one hex digit and you write the
        number you mean. High bit selects size, low bit selects space:
        `(is_8bit << 1) | is_virtual`.

        This deliberately occupies the full nibble rather than bits 18-19,
        so the digit you type is the value you get. An earlier revision
        packed it into the top two bits of this nibble, which meant field 3
        rendered as the digit `C` - correct but unwritable by hand.

        OLD CODES: the original layout was a single size bit at 19, always
        physical, giving digit 0 (16-bit) or 8 (8-bit). Digit 0 still means
        16-bit physical, unchanged. Digit 8 no longer decodes as 8-bit and
        must be rewritten as 2. See convert_d_size_nibble().
        """
        field = (val >> 16) & 0xF
        return bool(field & 0x2), bool(field & 0x1)   # (is_8bit, is_virtual)

    def _d_read(self, offset, is_8bit, is_virtual, mem_file):
        """Read a type D/E compare value, translating first if virtual."""
        if is_virtual:
            if self.pagemap is None:
                if self.refresh_pagemap(mem_file) is None:
                    return None
            else:
                self.pagemap.mem_file = mem_file
                if self._pagemap_is_stale(mem_file):
                    self.pagemap.invalidate()
            phys = self.pagemap.to_phys(offset)
            if phys is None:
                return None
        else:
            phys = offset
        return self._r8(phys, mem_file) if is_8bit else self._r16(phys, mem_file)

    def _typeD(self, codes, idx, cmd, val, code_type, mem_file):
        """
        Type 0xD - conditional. Guards the next N lines.

            Daaaaaaa NNTavvvv    a(cmd) = 28-bit offset, PHYSICAL or VIRTUAL
                                 v = 16-bit compare value
                                 a(val, bits 16-19) = size + address space,
                                     one hex digit: 0=16-bit phys, 1=16-bit
                                     virt, 2=8-bit phys, 3=8-bit virt
                                 T = test (bits 20-22)
                                 N = lines guarded (bits 24-31)

        Tests: 0 ==, 1 !=, 2 <, 3 >, 4 AND==0, 5 AND!=0, 6 OR==0, 7 OR!=0.

        Type E was the same comparison with the fields laid out differently and
        is retired; D expresses everything it could. To convert an old E code:

            offset  = E_val & 0x0FFFFFFF
            compare = E_cmd & 0xFFFF
            test    = (E_val >> 28) & 7
            is_8bit = ((E_cmd >> 24) & 0xF) == 1
            n       = (E_cmd >> 16) & 0xFF

            D_cmd = 0xD0000000 | offset
            D_val = (n << 24) | (test << 20) | (is_8bit << 17) | compare

        (That formula still produces a valid D code - it only ever sets bit
        19, never bit 18, so the result is always the physical variant. To
        target virtual space instead, also OR in `1 << 18`.)
        """
        n = self._d_n(cmd, val, code_type)
        offset = cmd & 0x0FFFFFFF
        compare_val = val & 0xFFFF
        test = (val >> 20) & 0x7
        is_8bit, is_virtual = self._d_addr_space(val)
        mem_val = self._d_read(offset, is_8bit, is_virtual, mem_file)
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

    def _typeE(self, codes, idx, cmd, val, mem_file, bid):
        """
        Type 0xE - conditional ON/OFF SWITCH. Guards the next N lines.

            Eaaaaaaa NNTavvvv    a(cmd) = 28-bit offset, PHYSICAL or VIRTUAL
                                 v = 16-bit compare value
                                 a(val, bits 16-19) = size + address space,
                                     one hex digit: 0=16-bit phys, 1=16-bit
                                     virt, 2=8-bit phys, 3=8-bit virt
                                 T = test (bits 20-22)
                                 N = lines guarded (bits 24-31)

        Field layout is now IDENTICAL to type D, bit for bit - not just
        similar. A switch always starts OFF, so there is no initial-state
        bit to carve out; a D code becomes an E code by changing one nibble
        in the type and nothing else. (An earlier revision spent bit 23 on
        an initial-on flag; that's gone; bit 23 is unused, same as in D.)

        WHAT MAKES IT A SWITCH
        ----------------------
        D asks "is the condition true right now" and guards its lines on the
        answer. E asks the same question but uses it as an EDGE: the switch
        flips only on a false -> true transition, and the guarded lines run
        while the switch is on, whether or not the condition still holds.

        Modelled on Gecko's CC on/off switch. The point is button toggles. A D
        code testing a held button applies its lines only while held, and at 60
        ticks a second a "press to toggle" written with D would flicker on and
        off for as long as the button is down. E flips once per press and stays
        put.

            E00A6B24 03020020    press X (mask 0x20) to toggle the next 3 lines
            0012C4E0 00000063
            0012C4E4 00000063
            0012C4E8 00000063

        STATE
        -----
        Held per (block id, line index), so two switches in one cheat are
        independent and a switch survives the freeze loop's next pass. Cleared
        when the game is deactivated - a switch left on from a previous session
        would silently apply its lines the moment the next game attached.

        The edge is tracked separately from the state: `prev` remembers whether
        the condition held last tick, so releasing and re-pressing is what
        flips it. Without that, holding the button would toggle every tick and
        the switch would be a very fast blinker.
        """
        n = self._d_n(cmd, val, 0xE)
        offset = cmd & 0x0FFFFFFF
        compare_val = val & 0xFFFF
        test = (val >> 20) & 0x7
        is_8bit, is_virtual = self._d_addr_space(val)

        key = (bid, idx)
        st = self._switches.get(key)
        if st is None:
            st = {'on': False, 'prev': False}   # always starts off
            self._switches[key] = st

        mem_val = self._d_read(offset, is_8bit, is_virtual, mem_file)
        if mem_val is None:
            # Unreadable address: hold the switch where it is rather than
            # guessing, and keep guarding on its current state. A failed read
            # is not a button release, and it is certainly not permission to
            # run the guarded lines.
            return idx + 1 if st['on'] else idx + 1 + n

        if test == 0:   cond = mem_val == compare_val
        elif test == 1: cond = mem_val != compare_val
        elif test == 2: cond = mem_val < compare_val
        elif test == 3: cond = mem_val > compare_val
        elif test == 4: cond = not (mem_val & compare_val)
        elif test == 5: cond = (mem_val & compare_val) != 0
        elif test == 6: cond = (mem_val | compare_val) == 0
        else:           cond = (mem_val | compare_val) != 0

        if cond and not st['prev']:
            st['on'] = not st['on']
        st['prev'] = cond

        return idx + 1 if st['on'] else idx + 1 + n

    def clear_switches(self, bid=None):
        """
        Forget switch states. All of them, or one cheat's.

        Called when a game is deactivated. A switch that stayed on across a
        game change would apply its guarded lines immediately on the next
        attach, with no button pressed and nothing on screen to explain it.
        """
        if bid is None:
            self._switches.clear()
        else:
            for k in [k for k in self._switches if k[0] == bid]:
                del self._switches[k]

    def apply_all(self, blocks, mem_file=None):
        for blk in blocks:
            if blk.get('enabled', False):
                self.execute_block(blk, mem_file)

