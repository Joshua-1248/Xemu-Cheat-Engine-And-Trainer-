"""Guest page-table translation and pointer-chain scanning.

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
from .regions import KSEG_BASE, RAM_MASK_LO, detect_xbe_region  # noqa: F401


class XboxPageMap:
    """
    Guest virtual <-> physical translation, read out of the Xbox page tables.

    This exists because xemu's RAM block is *physical* memory while the pointers
    a game stores are *virtual* addresses. In a real dump virtual 0x00010000
    lived at physical 0x005B2000 - so indexing pointers by physical offset
    compares unrelated numbers, and a scan finds strictly less than chance.
    Confirmed against a retail title: the page directory sits at physical
    0x0000F000 with the usual self-referencing entry at PDE[768], and the XBE's
    declared base translated to exactly where the 'XBEH' header was found.
    """

    NONE = 0xFFFFFFFF
    PD_PHYS = 0x0000F000

    __slots__ = ('v2p', 'p2v', 'ram_size', 'pd_phys', 'engine', '_cache',
                 '_rev', '_rev_time', '_cache_time')

    @classmethod
    def on_demand(cls, engine):
        """
        Translator that walks the live page tables per lookup.

        Building the whole map reads all of RAM (~4 s for 128 MB). Interactive
        use needs a handful of translations, so walking on demand is 8 bytes per
        lookup instead.

        Walking is stale-proof; the CACHE in front of it is not, and that
        distinction cost a real bug. Cached page translations were kept for the
        life of the process, so once the guest remapped a heap page - which it
        does on every level load - a pointer chain read its intermediate
        pointers out of whatever now occupied the old frame, got garbage, and
        the address table showed "Error" for a chain that was perfectly
        correct. Entries now expire; a miss costs one PDE and one PTE read.
        """
        o = cls.__new__(cls)
        o.v2p = o.p2v = None
        o._rev = None
        o._rev_time = 0.0
        o.engine = engine
        o.ram_size = engine.xbox_ram_size_mb * 1024 * 1024
        o.pd_phys = cls.PD_PHYS
        o._cache = {}
        o._cache_time = 0.0
        return o

    REVERSE_TTL = 2.0        # seconds; the guest remaps pages as it runs
    CACHE_TTL = 0.5          # seconds; forward translations go stale the same way

    def _reverse_index(self):
        """{physical frame: virtual page} for the on-demand translator."""
        now = time.time()
        cached = getattr(self, '_rev', None)
        if cached is not None and now - getattr(self, '_rev_time', 0) < \
                self.REVERSE_TTL:
            return cached

        def rd(pa, n):
            try:
                raw = self.engine.read_mem(self.engine.xbox_ram_base + pa, n)
                return raw if len(raw) == n else None
            except Exception:
                return None

        pd = rd(self.pd_phys, 0x1000)
        if pd is None:
            return None
        rev = {}
        for i in range(1024):
            e = struct.unpack_from("<I", pd, i * 4)[0]
            if not (e & 1):
                continue
            if e & 0x80:                       # 4 MB page
                base = (e & 0xFFC00000) >> 12
                for k in range(1024):
                    rev.setdefault(base + k, (i << 10) + k)
                continue
            pt = rd(e & 0xFFFFF000, 0x1000)
            if pt is None:
                continue
            for j in range(1024):
                pte = struct.unpack_from("<I", pt, j * 4)[0]
                if pte & 1:
                    # setdefault: several virtual pages can share one frame,
                    # and the first mapping found is as good as any.
                    rev.setdefault(pte >> 12, (i << 10) + j)
        self._rev, self._rev_time = rev, now
        return rev

    def _rd_phys32(self, pa):
        try:
            raw = self.engine.read_mem(self.engine.xbox_ram_base + pa, 4)
            return None if len(raw) < 4 else struct.unpack("<I", raw)[0]
        except Exception:
            return None

    def _walk(self, va):
        page = va >> 12
        now = time.time()
        if now - getattr(self, '_cache_time', 0.0) > self.CACHE_TTL:
            self._cache.clear()
            self._cache_time = now
        hit = self._cache.get(page)
        if hit is not None:
            return hit + (va & 0xFFF)
        pde = self._rd_phys32(self.pd_phys + ((va >> 22) * 4))
        if pde is None or not (pde & 1):
            return None
        if pde & 0x80:
            base = (pde & 0xFFC00000) | (va & 0x003FF000)
        else:
            pte = self._rd_phys32((pde & 0xFFFFF000) + (((va >> 12) & 0x3FF) * 4))
            if pte is None or not (pte & 1):
                return None
            base = pte & 0xFFFFF000
        if base >= self.ram_size:
            return None
        if len(self._cache) < 8192:
            self._cache[page] = base
        return base + (va & 0xFFF)

    def invalidate(self):
        self._cache.clear()
        self._cache_time = 0.0
        self._rev = None

    def __init__(self, dump, pd_phys=PD_PHYS):
        n = len(dump)
        u32 = np.frombuffer(dump[:(n // 4) * 4], dtype='<u4')
        NONE = np.uint32(self.NONE)
        v2p = np.full(1 << 20, NONE, dtype=np.uint32)
        pd = u32[pd_phys // 4: pd_phys // 4 + 1024]

        for i in range(1024):
            e = int(pd[i])
            if not (e & 1):
                continue
            if e & 0x80:                                  # 4 MB large page
                v2p[i << 10:(i << 10) + 1024] = (
                    np.arange(1024, dtype=np.uint32)
                    + np.uint32((e & 0xFFC00000) >> 12))
                continue
            pt = e & 0xFFFFF000
            if pt + 0x1000 > n:
                continue
            ptes = u32[pt // 4: pt // 4 + 1024]
            idx = np.nonzero((ptes & 1) != 0)[0]
            if idx.size:
                v2p[(i << 10) + idx] = (ptes[idx] >> 12).astype(np.uint32)

        p2v = np.full(max(1, n // 0x1000), NONE, dtype=np.uint32)
        mapped = np.nonzero(v2p != NONE)[0]
        pp = v2p[mapped]
        inb = pp < (n // 0x1000)
        p2v[pp[inb]] = mapped[inb].astype(np.uint32)

        self.v2p, self.p2v, self.ram_size, self.pd_phys = v2p, p2v, n, pd_phys

    @property
    def valid(self):
        if self.v2p is None:
            return self._walk(0x00010000) is not None
        return int((self.v2p != self.NONE).sum()) > 64

    def to_phys(self, va):
        if self.v2p is None:
            return self._walk(va)
        p = self.v2p[(va >> 12) & 0xFFFFF]
        if p == self.NONE:
            return None
        p = int(p) * 0x1000 + (va & 0xFFF)
        return p if p < self.ram_size else None

    def to_virt(self, pa):
        if self.p2v is None:
            # The on-demand translator only walks virtual -> physical, so it
            # has no reverse map and this used to return None every time -
            # which is what made "find what accesses" reject every plain
            # address entry. Build a frame -> virtual page index instead; it
            # costs one 4 KB read per present page table, not a scan of RAM.
            rev = self._reverse_index()
            if rev is None:
                return None
            vpg = rev.get(pa >> 12)
            return None if vpg is None else (vpg << 12) | (pa & 0xFFF)
        pg = pa >> 12
        if pg >= self.p2v.size:
            return None
        v = self.p2v[pg]
        return None if v == self.NONE else int(v) * 0x1000 + (pa & 0xFFF)

    def regions(self, min_pages=16):
        """
        Contiguous mapped virtual runs, largest first.

        Preferable to a hardcoded list for anything kernel-allocated: in a real
        dump the 0xD0000000 window began at 0xD0008000, not at 0xD0000000, and
        that start address is not something to guess at per-title.
        """
        v = self.v2p
        mapped = np.nonzero(v != np.uint32(self.NONE))[0]
        if mapped.size == 0:
            return []
        brk = np.nonzero(np.diff(mapped) != 1)[0]
        starts = np.concatenate(([mapped[0]], mapped[brk + 1]))
        ends = np.concatenate((mapped[brk], [mapped[-1]]))
        out = []
        for a, b in zip(starts, ends):
            if (b - a + 1) < min_pages:
                continue
            out.append((int(a) * 0x1000, (int(b) + 1) * 0x1000,
                        int(v[a]) * 0x1000))
        out.sort(key=lambda r: r[1] - r[0], reverse=True)
        return out

    def readable_pages(self):
        """Mapped virtual pages that live inside the dump (excludes MMIO)."""
        vp = np.nonzero(self.v2p != self.NONE)[0]
        pp = self.v2p[vp].astype(np.int64)
        return vp[(pp < self.ram_size // 0x1000) & (vp < 0xF0000)]

class PointerMap:
    """
    An index of every plausible pointer in a RAM snapshot, keyed by target.

    src : RAM offset where the pointer dword lives
    dst : RAM offset the pointer points to (normalized out of the 0x8xxxxxxx
          window if necessary)
    Both are kept sorted by dst so a "who points into [lo, hi]?" query is a
    pair of binary searches.
    """

    __slots__ = ('src', 'dst', 'ram_size', 'xbe_base', 'xbe_size',
                 '_by_src', 'xbe_found', 'virtual')

    @staticmethod
    def _build_virtual(arr, pm, align):
        vp = pm.readable_pages()
        if vp.size == 0:
            return (np.zeros(0, dtype=np.uint32),) * 2
        pp = pm.v2p[vp].astype(np.int64)
        didx = (pp[:, None] * 1024 + np.arange(1024)).ravel()
        didx = didx[didx < arr.size]
        vals = arr[didx]
        srcv = (vp[:, None].astype(np.int64) * 4096
                + np.arange(0, 4096, 4)).ravel()[:didx.size]
        vpg = (vals >> 12).astype(np.int64)
        ok = (vals >= RAM_MASK_LO) & (vpg < (1 << 20))
        if align > 1:
            ok &= (vals & (align - 1)) == 0
        ok[ok] &= pm.v2p[vpg[ok]] != np.uint32(XboxPageMap.NONE)
        return srcv[ok].astype(np.uint32), vals[ok].astype(np.uint32)

    def __init__(self, dump, ram_size, align=2, pagemap=None):
        usable = (min(len(dump), ram_size) // 4) * 4
        arr = np.frombuffer(dump[:usable], dtype='<u4')

        if pagemap is not None and pagemap.valid:
            # Virtual address space: index by the addresses the game actually
            # uses. src and dst are both guest virtual addresses.
            src, dst = self._build_virtual(arr, pagemap, align)
            self.virtual = True
        else:
            lo_ok = (arr >= RAM_MASK_LO) & (arr < ram_size)
            hi_ok = (arr >= KSEG_BASE) & (arr < KSEG_BASE + ram_size)
            valid = lo_ok | hi_ok
            if align > 1:
                # NB: 2, not 4. DOOM 3 Xbox allocates objects on 2-byte
                # boundaries - its player object sat at 0x01215466 - so a
                # 4-byte filter silently discards most real object pointers.
                valid &= (arr & (align - 1)) == 0
            idx = np.nonzero(valid)[0]
            dst = np.where(hi_ok[idx], arr[idx] - KSEG_BASE,
                           arr[idx]).astype(np.uint32)
            src = (idx * 4).astype(np.uint32)
            self.virtual = False

        order = np.argsort(dst, kind='stable')
        self.dst = dst[order]
        self.src = src[order]
        self.ram_size = 0xF0000000 if getattr(self, 'virtual', False) \
                        else ram_size
        self._by_src = None
        b, sz = detect_xbe_region(dump, ram_size)
        if b is not None and getattr(self, 'virtual', False):
            # Chains are in virtual space, so the static region is the image's
            # VIRTUAL range - which is fixed across boots, unlike its physical
            # location. This makes the 'XBE bases only' filter genuinely useful.
            vb = struct.unpack_from('<I', dump, b + 0x104)[0] & 0x0FFFFFFF
            vs = struct.unpack_from('<I', dump, b + 0x10C)[0]
            if 0x1000 <= vs <= 0x8000000:
                b, sz = vb, vs
        self.xbe_found = b is not None
        # Fallback only; with xbe_found False the caller should not rely on it.
        self.xbe_base = b if b is not None else 0x00010000
        self.xbe_size = sz if sz is not None else \
            min(ram_size, 0x00400000) - 0x00010000

    def __len__(self):
        return int(self.src.size)

    def in_static(self, offs):
        return (offs >= self.xbe_base) & (offs < self.xbe_base + self.xbe_size)

    def pointers_into(self, targets, max_offset):
        """
        Vectorized reverse lookup.

        For each target offset t, find every pointer whose destination lies in
        [t - max_offset, t]. Returns (parent_idx, src, struct_offset) where
        parent_idx indexes back into `targets`.
        """
        targets = np.asarray(targets, dtype=np.int64)
        lows = np.clip(targets - max_offset, 0, None).astype(np.uint32)
        highs = targets.astype(np.uint32)

        lo_i = np.searchsorted(self.dst, lows, side='left')
        hi_i = np.searchsorted(self.dst, highs, side='right')
        counts = (hi_i - lo_i).astype(np.int64)
        total = int(counts.sum())
        if total == 0:
            empty = np.empty(0, dtype=np.int64)
            return empty, empty.astype(np.uint32), empty

        # Expand variable-length index ranges without a Python loop.
        starts = np.repeat(lo_i, counts)
        ramp = np.arange(total, dtype=np.int64) - np.repeat(
            np.concatenate(([0], np.cumsum(counts)[:-1])), counts)
        flat = starts + ramp

        parent = np.repeat(np.arange(targets.size, dtype=np.int64), counts)
        src = self.src[flat]
        struct_off = np.repeat(targets, counts) - self.dst[flat].astype(np.int64)
        return parent, src, struct_off

def scan_chains(pmap, target_off, max_offset=0x1000, max_depth=4,
                node_cap=400000, frontier_cap=150000, max_results=50000,
                static_only=False):
    """
    Breadth-first backwards walk from `target_off`.

    Returns a list of (base_offset, [offsets...]) where resolution follows the
    standard Cheat Engine convention:
        addr = [[[base] + o0] + o1] ... + o_last
    """
    results = []
    seen = set()
    levels = []            # per depth: (parent, src, soff)
    frontier_map = [None]  # frontier_map[d][k] -> index into levels[d-1].src
    frontier = np.array([target_off], dtype=np.int64)

    for depth in range(max_depth):
        # Expand in chunks: a wide frontier crossed with a 0x1000 window can
        # produce tens of millions of hits, which is both slow and a memory
        # hazard if materialized in one shot.
        p_acc, s_acc, o_acc = [], [], []
        got = 0
        for c0 in range(0, frontier.size, 65536):
            chunk = frontier[c0:c0 + 65536]
            p, sr, so = pmap.pointers_into(chunk, max_offset)
            if sr.size:
                p_acc.append(p + c0); s_acc.append(sr); o_acc.append(so)
                got += sr.size
            if got >= node_cap * 4:
                break
        if not s_acc:
            break
        parent = np.concatenate(p_acc)
        src = np.concatenate(s_acc)
        soff = np.concatenate(o_acc)

        if src.size > node_cap:
            # Prefer the tightest struct offsets: a pointer to the head of an
            # object is far likelier to be the real parent than one landing
            # 0xF00 bytes into it.
            keep = np.sort(np.argsort(soff, kind='stable')[:node_cap])
            parent, src, soff = parent[keep], src[keep], soff[keep]
        levels.append((parent, src, soff))

        static = pmap.in_static(src.astype(np.int64))
        # Deciding what counts as a stable base by guessing at the XBE image is
        # fragile - on this hardware the image is paged, so its physical offset
        # is not predictable and detection can fail outright. Emitting a
        # candidate at every level instead, and letting cross-snapshot
        # verification decide which bases are actually stable, needs no such
        # guess. static_only is kept for when the region IS known good.
        emit = np.nonzero(static)[0] if static_only \
               else np.argsort(np.abs(soff), kind='stable')
        for i in emit:
            chain = _rebuild(levels, frontier_map, depth, int(i))
            key = (chain[0], tuple(chain[1]))
            if key in seen:
                continue
            seen.add(key)
            results.append(chain)
            if len(results) >= max_results:
                return results

        # Next level looks for pointers into the slots we just found. Static
        # slots are already complete chains, so only dynamic ones continue.
        dyn = np.nonzero(~static)[0]
        if dyn.size == 0:
            break
        if dyn.size > frontier_cap:
            dyn = dyn[np.sort(np.argsort(soff[dyn], kind='stable')[:frontier_cap])]
        frontier = src[dyn].astype(np.int64)
        frontier_map.append(dyn)

    return results

def _rebuild(levels, frontier_map, depth, idx):
    """Walk the backlinks to produce (base_offset, [offsets...])."""
    offsets = []
    d, i = depth, idx
    base = int(levels[depth][1][idx])   # the static slot itself
    while True:
        parent, src, soff = levels[d]
        # Discovered deepest-first, which is already application order:
        # read32(base) + offsets[0] -> read32(...) + offsets[1] -> ... -> target
        offsets.append(int(soff[i]))
        if d == 0:
            break
        i = int(frontier_map[d][int(parent[i])])
        d -= 1
    return base, offsets

def resolve_with_index(pmap, base, offsets):
    """
    Resolve a chain using only a saved pointer index (no raw dump needed).

    The index stores every plausible pointer as (src -> dst), which is exactly
    what a dereference needs. A slot missing from the index means it did not
    hold a valid pointer in that snapshot, so the chain is dead there anyway.
    """
    if getattr(pmap, '_by_src', None) is None:
        order = np.argsort(pmap.src, kind='stable')
        pmap._by_src = (pmap.src[order], pmap.dst[order])
    ssrc, sdst = pmap._by_src
    cur = base
    for i, off in enumerate(offsets):
        j = np.searchsorted(ssrc, np.uint32(cur))
        if j >= ssrc.size or int(ssrc[j]) != cur:
            return None
        cur = int(sdst[j]) + off
        if i == len(offsets) - 1:
            return cur
        if not (0 <= cur < pmap.ram_size):
            return None
    return cur

def scan_chains_verified(pa, ta, pb, tb, max_offset=0x1000, max_depth=4,
                         frontier_cap=150000, max_results=20000, tolerance=0,
                         static_only=False):
    """
    Walk snapshot A backwards from the target, verifying against snapshot B at
    every level.

    Two approaches that do NOT work here, for the record:

      * Requiring chains to end inside the XBE image. The Xbox pages the image
        in, so its offset in xemu's flat RAM block is not predictable and
        detection can fail entirely - as it does on this title.

      * Intersecting the two snapshots level by level. Tempting, but only the
        base slot keeps its offset across a reboot; every intermediate slot
        lives inside a heap object that has moved, so the intersection is
        empty by construction.

    Verifying per level (rather than collecting everything and verifying at
    the end) is what keeps this tractable: candidate counts grow by roughly
    40x per level, so a global result cap discards the real chain long before
    verification ever looks at it. Here only survivors accumulate.
    """
    results = []
    seen = set()
    levels = []
    frontier_map = [None]
    frontier = np.array([ta], dtype=np.int64)

    for depth in range(max_depth):
        p_acc, s_acc, o_acc, got = [], [], [], 0
        for c0 in range(0, frontier.size, 65536):
            p, sr, so = pa.pointers_into(frontier[c0:c0 + 65536], max_offset)
            if sr.size:
                p_acc.append(p + c0); s_acc.append(sr); o_acc.append(so)
                got += sr.size
            if got >= frontier_cap * 8:
                break
        if not s_acc:
            break
        parent = np.concatenate(p_acc)
        src = np.concatenate(s_acc)
        soff = np.concatenate(o_acc)
        order = np.argsort(np.abs(soff), kind='stable')
        if src.size > frontier_cap * 4:
            keep = np.sort(order[:frontier_cap * 4])
            parent, src, soff = parent[keep], src[keep], soff[keep]
            order = np.argsort(np.abs(soff), kind='stable')
        levels.append((parent, src, soff))

        batch = [_rebuild(levels, frontier_map, depth, int(i)) for i in order]
        if static_only:
            batch = [c for c in batch if pa.in_static(np.int64(c[0]))]
        for chain in verify_chains_index(pb, batch, tb, tolerance):
            key = (chain[0], tuple(chain[1]))
            if key in seen:
                continue
            seen.add(key)
            results.append(chain)
            if len(results) >= max_results:
                return results

        keep = order[:frontier_cap] if order.size > frontier_cap else order
        keep = np.sort(keep)
        frontier = src[keep].astype(np.int64)
        frontier_map.append(keep)

    return results

def verify_chains_index(pmap, chains, target_off, tolerance=0):
    """
    Vectorized verification against a saved index. Chains are grouped by depth
    so each dereference level is one batched searchsorted instead of one call
    per chain - with static_only off the candidate list runs to six figures.
    """
    if getattr(pmap, '_by_src', None) is None:
        order = np.argsort(pmap.src, kind='stable')
        pmap._by_src = (pmap.src[order], pmap.dst[order])
    ssrc, sdst = pmap._by_src
    kept = []
    by_depth = {}
    for c in chains:
        by_depth.setdefault(len(c[1]), []).append(c)

    for depth, group in by_depth.items():
        cur = np.array([c[0] for c in group], dtype=np.int64)
        alive = np.ones(cur.size, dtype=bool)
        for lvl in range(depth):
            j = np.searchsorted(ssrc, cur.clip(0, None).astype(np.uint32))
            j = np.minimum(j, ssrc.size - 1)
            hit = ssrc[j].astype(np.int64) == cur
            alive &= hit
            if not alive.any():
                break
            cur = np.where(hit, sdst[j].astype(np.int64), 0) + \
                  np.array([c[1][lvl] for c in group], dtype=np.int64)
            if lvl < depth - 1:
                alive &= (cur >= 0) & (cur < pmap.ram_size)
        ok = alive & (np.abs(cur - target_off) <= tolerance)
        kept.extend(group[k] for k in np.nonzero(ok)[0])
    return kept

def verify_chains(chains, dump2, ram_size, target2_off, tolerance=0):
    """
    Re-resolve every chain against a second snapshot (taken after a restart or
    a level reload) and keep only the ones that still land on the value.
    This is what separates a real static pointer from 2000 coincidences.
    """
    n = min(len(dump2), ram_size)
    kept = []
    for base, offsets in chains:
        cur = base
        ok = True
        for off in offsets:
            # Every offset in the chain follows a dereference, including the
            # last one: addr = [[[base]+o0]+o1]+o2
            if cur + 4 > n:
                ok = False
                break
            v = struct.unpack_from('<I', dump2, cur)[0]
            if KSEG_BASE <= v < KSEG_BASE + ram_size:
                v -= KSEG_BASE
            elif not (RAM_MASK_LO <= v < ram_size):
                ok = False
                break
            cur = v + off
        if ok and abs(cur - target2_off) <= tolerance:
            kept.append((base, offsets))
    return kept
