"""Function discovery, symbol loading, RTTI/string cross-referencing.

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


class FunctionIndex:
    """Discovered functions for the loaded title, from every available source."""

    # Bytes that plausibly begin a function. Deliberately loose - this is only
    # used to reject call targets that land in the middle of data, so a false
    # accept costs a spurious sub_ entry while a false reject loses a real
    # function.
    START_BYTES = frozenset((
        0x55,                                     # push ebp
        0x53, 0x56, 0x57, 0x51, 0x52, 0x50,       # push ebx/esi/edi/ecx/edx/eax
        0x83, 0x81,                               # sub esp, imm
        0x8B, 0x89, 0x8D, 0xA1, 0xA0, 0xA3,       # mov / lea
        0x6A, 0x68,                               # push imm
        0xB8, 0xB9, 0xBA, 0xBB, 0xBE, 0xBF,       # mov reg, imm32
        0x33, 0x31, 0x85, 0x84,                   # xor / test
        0xE9, 0xEB, 0xFF,                         # jmp thunks
        0xC3, 0xC2,                               # ret (a stub, but real)
        0xD9, 0xF3, 0x0F, 0x64, 0x65))            # fpu / sse / prefixes

    PRIO = {"symbol": 6, "rtti": 5, "entry": 4, "string": 3, "call": 2,
            "prologue": 1}

    SOURCE_LABEL = {"symbol": "sym", "rtti": "rtti", "entry": "entry",
                    "string": "str", "call": "call", "prologue": "prologue"}

    # Strings worth naming a function after: source files, and the __FUNCTION__
    # style literals that assert macros pass.
    FILEISH = re.compile(r"^[\w\-. :\\/]{3,60}\.(?:c|cc|cpp|cxx|h|hpp|asm)$",
                         re.I)
    FUNCISH = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{3,60}"
                         r"(?:::[A-Za-z_~][A-Za-z0-9_]{0,60})?$")

    def __init__(self):
        self.names = {}          # va -> name
        self.source = {}         # va -> source key
        self.xrefs = {}          # va -> call count
        self.notes = {}          # va -> extra note (source file, etc)
        self.stats = {}          # source key -> count
        self.debug_info = []     # human-readable findings about symbols
        self.note = ""

    # ---- merging ---------------------------------------------------------
    def add(self, va, name, source, note=None):
        old = self.source.get(va)
        if old is not None and self.PRIO[old] >= self.PRIO[source]:
            if note and not self.notes.get(va):
                self.notes[va] = note
            return False
        self.names[va] = name
        self.source[va] = source
        if note:
            self.notes[va] = note
        return True

    def entries(self):
        """[(va, display name)] sorted by address, for the function list."""
        out = []
        for va in sorted(self.names):
            name = self.names[va]
            bits = []
            n = self.xrefs.get(va, 0)
            if n:
                bits.append(f"{n} xref" + ("s" if n != 1 else ""))
            note = self.notes.get(va)
            if note:
                bits.append(note)
            src = self.SOURCE_LABEL.get(self.source.get(va), "?")
            suffix = f"   [{src}" + (f", {', '.join(bits)}" if bits else "") + "]"
            out.append((va, name + suffix))
        return out

    def plain(self):
        """[(va, name)] with no decoration - what the code view annotates with."""
        return sorted(self.names.items())

    # ---- byte-level scanners --------------------------------------------
    @staticmethod
    def _u8(buf):
        if _HAVE_NUMPY:
            return np.frombuffer(buf, dtype=np.uint8)
        return None

    def _rel32_targets(self, buf, lo, opcode):
        """
        Targets of every `opcode rel32` in the buffer.

        A byte scan, not a disassembly: a full capstone sweep of a 6 MB .text
        means iterating a million-plus instructions in Python, several seconds,
        for information a vectorised byte scan gets in milliseconds. The cost is
        false positives from data that happens to contain the opcode byte, which
        is why every target is then validated against START_BYTES and the
        section bounds.
        """
        arr = self._u8(buf)
        n = len(buf)
        if arr is None:
            out = {}
            for i in range(n - 5):
                if buf[i] != opcode:
                    continue
                rel = int.from_bytes(buf[i + 1:i + 5], "little", signed=True)
                out[lo + i + 5 + rel] = out.get(lo + i + 5 + rel, 0) + 1
            return out
        idx = np.nonzero(arr[:n - 5] == opcode)[0].astype(np.int64)
        if not idx.size:
            return {}
        rel = (arr[idx + 1].astype(np.int64)
               | (arr[idx + 2].astype(np.int64) << 8)
               | (arr[idx + 3].astype(np.int64) << 16)
               | (arr[idx + 4].astype(np.int64) << 24))
        rel = np.where(rel >= 0x80000000, rel - 0x100000000, rel)
        tgt = lo + idx + 5 + rel
        vals, counts = np.unique(tgt, return_counts=True)
        return dict(zip(vals.tolist(), counts.tolist()))

    def _find_pattern(self, buf, pat):
        out, start = [], 0
        while True:
            i = buf.find(pat, start)
            if i < 0:
                return out
            out.append(i)
            start = i + 1

    def _prologues(self, buf, lo):
        """push ebp; mov ebp, esp - and the hot-patch pad MSVC puts before it."""
        found = set()
        for off in self._find_pattern(buf, b"\x55\x8b\xec"):
            found.add(lo + off)
        for off in self._find_pattern(buf, b"\x8b\xff\x55\x8b\xec"):
            found.discard(lo + off + 2)
            found.add(lo + off)
        return found

    def _after_padding(self, buf, lo, min_pad=3):
        """
        Addresses that follow alignment padding.

        The linker pads between functions with 0xCC (int3) or 0x90 (nop), so the
        first byte after a run of them is a function start far more often than
        chance. On its own that is weak evidence, so it only promotes an address
        that also looks like a function start.
        """
        arr = self._u8(buf)
        out = set()
        if arr is None:
            return out
        for pad in (0xCC, 0x90):
            is_pad = (arr == pad).astype(np.int8)
            # End of a run: pad at i, not pad at i+1.
            ends = np.nonzero((is_pad[:-1] == 1) & (is_pad[1:] == 0))[0]
            if not ends.size:
                continue
            for e in ends.tolist():
                if e + 1 >= len(arr):
                    continue
                if e - min_pad + 1 < 0 or not is_pad[e - min_pad + 1:e + 1].all():
                    continue
                if int(arr[e + 1]) in self.START_BYTES:
                    out.add(lo + e + 1)
        return out

    def _string_pool(self, regions):
        """{va: text} for printable literals in the read-only regions."""
        pool = {}
        for lo, buf in regions:
            for m in re.finditer(rb"[\x20-\x7e]{4,80}\x00", buf):
                pool[lo + m.start()] = m.group()[:-1].decode("ascii", "replace")
        return pool

    def _string_refs(self, buf, lo, pool):
        """
        Sites that push or load the address of a string literal.

        `push offset "foo.cpp"` is `68 <imm32>`, and `mov reg, offset str` is
        `B8+r <imm32>`; both are trivially recognisable by byte and are how
        assert macros pass __FILE__.
        """
        arr = self._u8(buf)
        if arr is None or not pool:
            return []
        opcodes = np.array([0x68, 0xB8, 0xB9, 0xBA, 0xBB, 0xBE, 0xBF, 0xBD],
                           dtype=np.uint8)
        idx = np.nonzero(np.isin(arr[:len(arr) - 5], opcodes))[0].astype(np.int64)
        if not idx.size:
            return []
        imm = (arr[idx + 1].astype(np.int64)
               | (arr[idx + 2].astype(np.int64) << 8)
               | (arr[idx + 3].astype(np.int64) << 16)
               | (arr[idx + 4].astype(np.int64) << 24))
        keys = np.fromiter(pool.keys(), dtype=np.int64, count=len(pool))
        hit = np.isin(imm, keys)
        return [(lo + int(i), int(v))
                for i, v in zip(idx[hit].tolist(), imm[hit].tolist())]

    # ---- symbol files ----------------------------------------------------
    MAP_LINE = re.compile(
        r"^\s*[0-9a-fA-F]{4}:[0-9a-fA-F]{8}\s+(\S+)\s+([0-9a-fA-F]{8})\b")
    FLAT_LINE = re.compile(
        r"^\s*(?:0x)?([0-9a-fA-F]{6,8})\s*[:,\s]\s*(\S.*?)\s*$")

    @staticmethod
    def demangle(name):
        """
        Light MSVC demangle for the common shapes.

        A full demangler is out of scope; ?Think@idPlayer@@UAEXXZ ->
        idPlayer::Think covers the overwhelming majority of what a .map holds,
        and anything unrecognised is returned untouched rather than mangled
        further.
        """
        if not name.startswith("?"):
            return name.lstrip("_@")
        body = name[1:].split("@@", 1)[0]
        parts = [p for p in body.split("@") if p]
        if not parts:
            return name
        return "::".join(reversed(parts))

    def load_symbols(self, path, image=None, limit=400000):
        """
        Import symbols from a .map / .sym / "address name" text file.

        Returns (count, description). Addresses are taken as absolute virtual
        addresses; a linker map's Rva+Base column already is one. Anything
        outside the loaded image is dropped, which is also the check that the
        file belongs to this title - importing a map for the wrong build would
        otherwise scatter plausible-looking names over unrelated code.
        """
        added = kept = dropped = 0
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if added + dropped > limit:
                    break
                m = self.MAP_LINE.match(line)
                if m:
                    raw, va = m.group(1), int(m.group(2), 16)
                else:
                    m = self.FLAT_LINE.match(line)
                    if not m:
                        continue
                    va, raw = int(m.group(1), 16), m.group(2)
                    if " " in raw and not raw.split()[0].strip():
                        continue
                    raw = raw.split()[0]
                if image and not (image[0] <= va < image[1]):
                    dropped += 1
                    continue
                if self.add(va, self.demangle(raw), "symbol"):
                    added += 1
                kept += 1
        self.stats["symbol"] = self.stats.get("symbol", 0) + added
        desc = f"{added} symbol(s) imported from {os.path.basename(path)}"
        if dropped:
            desc += (f"; {dropped} line(s) fell outside the loaded image "
                     f"and were dropped - check the map matches this build")
        if kept and not added:
            desc += " (all of them already known from a better source)"
        return added, desc

    # ---- debug-info detection -------------------------------------------
    def detect_debug_info(self, header, regions, read):
        """
        Report whether this build carries any real symbol information.

        Three things are worth looking for and all three are cheap: the XBE
        header's debug path fields, a PDB signature left in the image by the
        linker, and a section actually named .debug. None of them yields
        symbols by itself - a PDB path is a filename, not data - but knowing
        the build referenced foo.pdb tells you what to go and find.
        """
        out = []
        # XBE header: debug pathname 0x14C, debug filename 0x150, debug
        # unicode filename 0x154 - between the PE fields and the kernel thunk
        # pointer at 0x158, which §4b already established.
        for label, off in (("debug path", 0x14C), ("debug filename", 0x150),
                           ("debug unicode filename", 0x154)):
            if header is None or off + 4 > len(header):
                continue
            ptr = struct.unpack_from("<I", header, off)[0]
            if not ptr:
                continue
            raw = read(ptr, 128)
            if not raw:
                continue
            if "unicode" in label:
                txt = raw.split(b"\0\0")[0].decode("utf-16-le", "replace")
            else:
                txt = raw.split(b"\0")[0].decode("latin1", "replace")
            txt = "".join(c for c in txt if 0x20 <= ord(c) < 0x7F)
            if len(txt) > 3:
                out.append(f"XBE {label}: {txt}")
        for sig in (b"RSDS", b"NB10"):
            for lo, buf in regions:
                i = buf.find(sig)
                if i >= 0:
                    tail = buf[i:i + 200]
                    m = re.search(rb"[\x20-\x7e]{4,120}\.pdb", tail)
                    if m:
                        out.append(f"{sig.decode()} PDB reference: "
                                   f"{m.group().decode('latin1')}")
                    break
        self.debug_info = out
        return out

    # ---- the scan --------------------------------------------------------
    def scan(self, read, sections, image=None, entry=None, header=None,
             progress=None):
        text = sections.get(".text")
        if not text:
            self.note = "no .text section - nothing to scan"
            return self
        tlo, thi = text
        if thi - tlo > 0x1000000:
            thi = tlo + 0x1000000
        if progress:
            progress("reading .text...")
        code = read(tlo, thi - tlo)
        if not code:
            self.note = "could not read .text - is a game running?"
            return self
        thi = tlo + len(code)

        def in_text(va):
            return tlo <= va < thi

        # ---- call and jump targets --------------------------------------
        if progress:
            progress("scanning call targets...")
        calls = self._rel32_targets(code, tlo, 0xE8)
        jmps = self._rel32_targets(code, tlo, 0xE9)
        pro = self._prologues(code, tlo)
        pad = self._after_padding(code, tlo)

        n_call = 0
        for va, cnt in calls.items():
            if not in_text(va):
                continue
            b = code[va - tlo]
            # Two or more independent call sites agreeing is enough on its own.
            # One is not: the rel32 of a real call contains arbitrary bytes, so
            # a stray 0xE8 inside data computes to a target whose first byte is
            # a plausible opcode about a third of the time. Measured on a
            # synthetic image, accepting those put the middle of a function in
            # the list. So a lone call site also has to land somewhere a
            # function plausibly starts: a prologue, just after alignment
            # padding, or on a 16-byte boundary, which is how the linker places
            # them and which the middle of an instruction stream rarely is.
            if cnt < 2 and not (b in self.START_BYTES
                                and (va in pro or va in pad or va % 16 == 0)):
                continue
            self.xrefs[va] = self.xrefs.get(va, 0) + cnt
            if self.add(va, f"sub_{va:08X}", "call"):
                n_call += 1
        # Tail-call and import jump thunks are functions too, but a jmp is also
        # every loop and branch in the program, so these need a prologue or a
        # padding boundary behind them before they count.
        n_jmp = 0
        for va, cnt in jmps.items():
            if not in_text(va) or (va not in pro and va not in pad):
                continue
            self.xrefs[va] = self.xrefs.get(va, 0) + cnt
            if self.add(va, f"sub_{va:08X}", "call"):
                n_jmp += 1

        n_pro = 0
        for va in pro:
            if self.add(va, f"sub_{va:08X}", "prologue"):
                n_pro += 1
        n_pad = 0
        for va in pad:
            if va in pro or va in calls:
                continue
            if self.add(va, f"sub_{va:08X}", "prologue"):
                n_pad += 1

        # ---- string cross-references ------------------------------------
        if progress:
            progress("cross-referencing strings...")
        ro = []
        for name in (".rdata", ".data"):
            rng = sections.get(name)
            if not rng:
                continue
            lo, hi = rng
            buf = read(lo, min(hi - lo, 0x400000))
            if buf:
                ro.append((lo, buf))
        pool = self._string_pool(ro)
        starts = sorted(self.names)
        n_str = 0
        if starts and pool:
            import bisect
            for site, strva in self._string_refs(code, tlo, pool):
                txt = pool.get(strva, "")
                if not (self.FILEISH.match(txt) or self.FUNCISH.match(txt)):
                    continue
                i = bisect.bisect_right(starts, site) - 1
                if i < 0:
                    continue
                fn = starts[i]
                if site - fn > 0x800:            # too far to be this function
                    continue
                short = txt.replace("\\", "/").split("/")[-1]
                if self.FILEISH.match(txt):
                    self.notes.setdefault(fn, short)
                elif self.add(fn, f"{short}?", "string", note="from a literal"):
                    n_str += 1

        if entry and in_text(entry):
            self.add(entry, "XBE entry point", "entry")

        self.detect_debug_info(header, ro, read)
        self.stats.update({"call": n_call + n_jmp, "prologue": n_pro + n_pad,
                           "string": n_str})
        self.note = (f"{len(self.names)} functions: {n_call} by call target, "
                     f"{n_jmp} jump thunks, {n_pro + n_pad} by prologue, "
                     f"{n_str} named from a literal")
        return self

    def merge_rtti(self, pairs):
        """Fold the RTTI vtable names in on top of what the code scan found."""
        n = 0
        for va, name in pairs:
            if self.add(va, name, "rtti"):
                n += 1
        self.stats["rtti"] = n
        return n

    def summary(self):
        bits = [f"{v} {k}" for k, v in sorted(self.stats.items())
                if v]
        return f"{len(self.names)} functions (" + ", ".join(bits) + ")"

