"""SendTable layout inference and class/field lookup.

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


class SendTableIndex:
    """Recovered Source field names, keyed by table and by offset."""

    IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{1,62}$")
    STRIDES = range(0x20, 0x90, 4)
    MAX_PROPS = 1024
    LAYOUT_SAMPLE = 400          # tables used to infer the layout

    def __init__(self):
        self.tables = {}         # "DT_Foo" -> [(offset, name, sub_table|None)]
        self.flat = {}           # "DT_Foo" -> {offset: name} incl. base tables
        self.by_offset = {}      # offset -> [(table, name)]
        self.layout = {}         # the inferred struct shape, for verification
        self.note = ""

    # ---- helpers ---------------------------------------------------------
    def _rd32(self, va):
        for lo, hi, buf in self.regions:
            if lo <= va and va + 4 <= hi:
                off = va - lo
                return int.from_bytes(buf[off:off + 4], "little")
        return None

    def _ident(self, va):
        """The identifier string at a virtual address, or None."""
        if va is None:
            return None
        for lo, hi, buf in self.regions:
            if lo <= va < hi:
                raw = buf[va - lo:va - lo + 64]
                end = raw.find(b"\0")
                if end <= 0:
                    return None
                try:
                    s = raw[:end].decode("ascii")
                except UnicodeDecodeError:
                    return None
                return s if self.IDENT.match(s) else None
        return None

    def _in_regions(self, va):
        return any(lo <= va < hi for lo, hi, _ in self.regions)

    # ---- scan ------------------------------------------------------------
    def scan(self, read, sections, progress=None):
        """
        read(va, n) -> bytes; sections is {'.data': (lo, hi), ...}.
        Returns self. self.tables is empty if nothing convincing was found.
        """
        self.regions = []
        for name in (".rdata", ".data", ".text"):
            rng = sections.get(name)
            if not rng:
                continue
            lo, hi = rng
            if hi - lo > 0x800000:            # sanity cap
                hi = lo + 0x800000
            buf = read(lo, hi - lo)
            if buf:
                self.regions.append((lo, lo + len(buf), buf))
        if not self.regions:
            self.note = "no .data / .rdata to scan"
            return self

        dt_names = self._find_dt_strings()
        if not dt_names:
            self.note = ("no DT_ table names found - this title is probably "
                         "not a Source engine game")
            return self
        sites = self._find_pointer_sites(dt_names)
        if progress:
            progress(f"{len(dt_names)} DT_ names, {len(sites)} references")
        if not sites:
            self.note = f"{len(dt_names)} DT_ names but nothing points at them"
            return self

        layout = self._infer_layout(sites)
        if layout is None:
            self.note = (f"{len(sites)} candidate tables but no consistent "
                         f"SendProp layout - the inference failed, so no names "
                         f"are reported rather than guessed ones")
            return self
        self.layout = layout
        self._collect(sites, layout, progress)
        self._flatten()
        props = sum(len(v) for v in self.tables.values())
        self.note = (f"{len(self.tables)} tables, {props} fields; record stride "
                     f"0x{layout['stride']:X}, name at +0x{layout['name']:X}, "
                     f"offset at +0x{layout['offset']:X}, "
                     f"nested table at "
                     + (f"+0x{layout['sub']:X}" if layout.get('sub') is not None
                        else "not found")
                     + f"; table: props +0x{layout['t_props']:X}, count "
                       f"+0x{layout['t_count']:X}")
        return self

    def _find_dt_strings(self):
        """Every "DT_..." string literal, as {va: name}."""
        out = {}
        for lo, hi, buf in self.regions:
            start = 0
            while True:
                i = buf.find(b"DT_", start)
                if i < 0:
                    break
                start = i + 1
                # A string literal starts after a NUL (or at the region start).
                if i and buf[i - 1] not in (0, 0xFF):
                    continue
                s = self._ident(lo + i)
                if s:
                    out[lo + i] = s
        return out

    def _find_pointer_sites(self, dt_names):
        """Addresses whose dword points at a DT_ string."""
        sites = []
        targets = set(dt_names)
        for lo, hi, buf in self.regions:
            n = (len(buf) // 4) * 4
            if _HAVE_NUMPY:
                arr = np.frombuffer(buf[:n], dtype="<u4")
                tgt = np.fromiter(targets, dtype="<u4", count=len(targets))
                hit = np.nonzero(np.isin(arr, tgt))[0]
                sites += [(lo + int(i) * 4, dt_names[int(arr[i])]) for i in hit]
            else:
                for off in range(0, n, 4):
                    v = int.from_bytes(buf[off:off + 4], "little")
                    if v in targets:
                        sites.append((lo + off, dt_names[v]))
        return sites

    def _infer_layout(self, sites):
        """
        Vote on the struct shape.

        For each candidate table, try every plausible position of the props
        pointer and count relative to the name pointer, and every stride and
        name-field position inside a record. A shape only scores when the first
        few records all yield distinct identifier strings, which random data
        does not do.
        """
        from collections import Counter
        votes = Counter()
        # The first record's name candidates depend only on the props pointer,
        # so they are cached: without this the same 36 string reads are redone
        # for every stride and every count candidate, which is the difference
        # between a few seconds and a few minutes on a real image.
        first_cache = {}
        for va, _name in sites[:self.LAYOUT_SAMPLE]:
            for t_props in range(-0x20, 0x24, 4):
                p = self._rd32(va + t_props)
                if p is None or not self._in_regions(p):
                    continue
                firsts = first_cache.get(p)
                if firsts is None:
                    firsts = first_cache[p] = {
                        k: self._ident(self._rd32(p + k))
                        for k in range(0, max(self.STRIDES), 4)}
                if not any(firsts.values()):
                    continue
                for t_count in range(-0x20, 0x24, 4):
                    if t_count == t_props:
                        continue
                    cnt = self._rd32(va + t_count)
                    if cnt is None or not 2 <= cnt <= self.MAX_PROPS:
                        continue
                    for stride in self.STRIDES:
                        for k in range(0, stride, 4):
                            if firsts.get(k) is None:
                                continue
                            names, ok = [], True
                            for i in range(min(cnt, 8)):
                                nm = (firsts[k] if i == 0 else
                                      self._ident(self._rd32(p + i * stride + k)))
                                if nm is None or nm in names:
                                    ok = False
                                    break
                                names.append(nm)
                            if not ok:
                                continue
                            # Weight by how many records the shape explains,
                            # and reward a count that matches where the names
                            # actually stop. Without that a too-small count
                            # field scores identically to the real one - it
                            # wins ties just as often and silently truncates
                            # every table.
                            past = self._ident(self._rd32(p + cnt * stride + k))
                            votes[(t_props, t_count, stride, k)] += (
                                len(names) + (8 if past is None else 0))
        if not votes:
            return None
        (t_props, t_count, stride, k), score = votes.most_common(1)[0]
        if score < 3:
            return None
        layout = {"t_props": t_props, "t_count": t_count, "stride": stride,
                  "name": k, "votes": score, "candidates": len(votes)}
        layout["offset"] = self._infer_offset_field(sites, layout)
        if layout["offset"] is None:
            return None
        layout["sub"], layout["sub_delta"] = self._infer_sub_field(sites, layout)
        return layout

    def _records(self, va, layout):
        """(props_base, count) for a table site, or None."""
        p = self._rd32(va + layout["t_props"])
        cnt = self._rd32(va + layout["t_count"])
        if p is None or cnt is None or not 1 <= cnt <= self.MAX_PROPS:
            return None
        if not self._in_regions(p):
            return None
        return p, cnt

    def _infer_offset_field(self, sites, layout):
        """
        The field offset is the dword that is a small integer in every record.

        Scored on distinctness rather than just range: several fields in a
        SendProp are small ints (bit counts, element counts, flags) but they
        repeat heavily across a table, whereas the byte offset of each field is
        almost always unique within one class.
        """
        from collections import Counter
        stride, name_k = layout["stride"], layout["name"]
        score = Counter()
        for va, _n in sites[:self.LAYOUT_SAMPLE]:
            rec = self._records(va, layout)
            if rec is None:
                continue
            p, cnt = rec
            cnt = min(cnt, 24)
            if cnt < 4:
                continue
            for j in range(0, stride, 4):
                if j == name_k:
                    continue
                vals = [self._rd32(p + i * stride + j) for i in range(cnt)]
                if any(v is None or v > 0x8000 for v in vals):
                    continue
                uniq = len(set(vals))
                if uniq < max(3, cnt * 3 // 4):
                    continue
                # Uniqueness alone is not enough: a SendProp also holds bit
                # counts, element counts and flags, and in a small table those
                # can all be distinct too. What separates a byte offset is
                # magnitude - fields at +0x40 and beyond are ordinary in a
                # Source class, while a bit count never exceeds 32.
                big = sum(1 for v in vals if v > 0x40)
                score[j] += uniq + 2 * big
        return score.most_common(1)[0][0] if score else None

    def _start_deltas(self, layout):
        """
        Where a nested-table pointer could point, relative to the name site.

        The address a SendProp holds for a nested table is the start of that
        SendTable struct, and the name pointer is not necessarily the first
        field - so the convention is voted on rather than assumed. Zero covers
        a name-first layout, t_props/t_count cover the props-first shape the PC
        SDK compiles to.
        """
        return sorted({0, layout["t_props"], layout["t_count"],
                       min(0, layout["t_props"], layout["t_count"])})

    def _infer_sub_field(self, sites, layout):
        """The dword that is null or points at another table we recognise."""
        from collections import Counter
        deltas = self._start_deltas(layout)
        by_delta = {d: {va + d for va, _n in sites} for d in deltas}
        score = Counter()
        for va, _n in sites[:self.LAYOUT_SAMPLE]:
            rec = self._records(va, layout)
            if rec is None:
                continue
            p, cnt = rec
            for j in range(0, layout["stride"], 4):
                if j in (layout["name"], layout["offset"]):
                    continue
                for d in deltas:
                    starts = by_delta[d]
                    hits = sum(1 for i in range(min(cnt, 16))
                               if self._rd32(p + i * layout["stride"] + j)
                               in starts)
                    if hits:
                        score[(j, d)] += hits
        if not score:
            return None, None
        (j, d), _ = score.most_common(1)[0]
        return j, d

    def _collect(self, sites, layout, progress=None):
        stride, k, joff = layout["stride"], layout["name"], layout["offset"]
        sub = layout.get("sub")
        # Keyed by struct start, because that is what a nested-table pointer
        # inside a SendProp holds - not necessarily the name-pointer site.
        delta = layout.get("sub_delta") or 0
        site_by_addr = {}
        for va, name in sites:
            site_by_addr.setdefault(va + delta, name)
        for va, name in sites:
            rec = self._records(va, layout)
            if rec is None:
                continue
            p, cnt = rec
            props = []
            for i in range(cnt):
                base = p + i * stride
                fname = self._ident(self._rd32(base + k))
                off = self._rd32(base + joff)
                if fname is None or off is None:
                    continue
                sub_va = self._rd32(base + sub) if sub is not None else None
                props.append((off, fname,
                              site_by_addr.get(sub_va) if sub_va else None))
            if props:
                # Duplicate table names happen (client and server copies); keep
                # the one with more fields rather than whichever came last.
                old = self.tables.get(name)
                if old is None or len(props) > len(old):
                    self.tables[name] = props
        if progress:
            progress(f"{len(self.tables)} tables collected")

    def _flatten(self):
        """Fold nested (base class) tables into each table's offset map."""
        def build(name, seen):
            if name in self.flat:
                return self.flat[name]
            if name in seen or name not in self.tables:
                return {}
            seen.add(name)
            out = {}
            for off, fname, subname in self.tables[name]:
                if subname and subname != name:
                    for soff, sname in build(subname, seen).items():
                        out.setdefault(off + soff, sname)
                    # A nested table also has a name of its own worth keeping.
                    out.setdefault(off, fname)
                else:
                    out[off] = fname
            self.flat[name] = out
            return out

        for name in list(self.tables):
            build(name, set())
        for tname, m in self.flat.items():
            for off, fname in m.items():
                self.by_offset.setdefault(off, [])
                if (tname, fname) not in self.by_offset[off]:
                    self.by_offset[off].append((tname, fname))

    # ---- lookup ----------------------------------------------------------
    def table_for_class(self, cls):
        """
        Map an RTTI class name to its SendTable.

        Source's convention is CWeapon357 -> DT_Weapon357, so the leading C is
        dropped and the match is case-insensitive. Falls back to a suffix match
        for the C_-prefixed client classes.
        """
        if not cls or not self.flat:
            return None
        cache = getattr(self, "_cls_cache", None)
        if cache is None:
            cache = self._cls_cache = {}
        if cls in cache:
            return cache[cls]
        stem = cls
        for pre in ("C_", "C"):
            if stem.startswith(pre) and len(stem) > len(pre):
                stem = stem[len(pre):]
                break
        want = "dt_" + stem.lower()
        found = None
        for name in self.flat:
            low = name.lower()
            if low == want:
                found = name
                break
            if found is None and low.endswith(stem.lower()):
                found = name
        cache[cls] = found
        return found

    def lookup(self, offset, cls=None, limit=2):
        """
        Name a struct offset. Class context first, then anything that fits.

        Ambiguity is real - hundreds of classes have a field at +0x1C - so an
        unqualified match is returned with its table name and a ? so it never
        reads as certain.
        """
        table = self.table_for_class(cls) if cls else None
        if table:
            hit = self.flat.get(table, {}).get(offset)
            if hit:
                return hit
        cands = self.by_offset.get(offset)
        if not cands:
            return None
        if len(cands) == 1:
            t, n = cands[0]
            return f"{n} ({t})"
        picked = ", ".join(f"{n} ({t})" for t, n in cands[:limit])
        more = f" +{len(cands) - limit}" if len(cands) > limit else ""
        return f"{picked}{more} ?"

