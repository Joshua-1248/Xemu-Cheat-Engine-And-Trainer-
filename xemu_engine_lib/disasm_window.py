"""Disassembly view with integrated debugger panels.

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
from .debug_session import Breakpoint, compile_condition, parse_stop_reply  # noqa: F401
from .func_index import FunctionIndex  # noqa: F401
from .gdb_broker import gdb_broker  # noqa: F401
from .gdb_client import GDB_X86_REGS, GdbStubError, disassemble_at  # noqa: F401
from .sendtables import SendTableIndex  # noqa: F401
from .ui_widgets import GDB_DEFAULT_HOST, GDB_DEFAULT_PORT, bind_wheel, bind_wheel_cycle, bind_wheel_number, popup_menu  # noqa: F401


class DisassemblyWindow(tk.Toplevel):
    """
    Disassembler with a function list on the left and code on the right.

    Function names come from MSVC RTTI. Every vtable in .rdata has a Complete
    Object Locator at vtable[-1] leading to the mangled class name, so a scan
    of .rdata yields "CWeapon357::vtable[12]" for a large share of the image -
    no symbols required. Anything else is listed as sub_ADDRESS once a prologue
    is found.

    The code view is virtualized the same way the scan results are: it holds a
    screenful of rows and re-disassembles as you scroll, so opening a 6 MB
    .text section is instant.
    """

    PROLOGUE = b"\x55\x8b\xec"          # push ebp; mov ebp, esp
    ROW_CAP = 400

    def __init__(self, master, engine, address=None):
        super().__init__(master)
        self.engine = engine
        self.title("Debugger")
        self.geometry("1180x820")
        self.configure(bg="#212121")
        self.funcs = []                  # [(va, name)]
        self.filtered = []
        self.top_va = None
        self.history = []
        self._rows = []
        self._scan_thread = None
        self.sections = {}               # {'.text': (lo, hi), ...}
        self.image = None                # (lo, hi) of the XBE image
        import queue
        self.inbox = queue.Queue()

        # Debugger state. Breakpoints live here rather than in the session so
        # they survive detaching and reattaching the stub - which happens every
        # time xemu's gdbserver is restarted.
        self.session = None
        self.breakpoints = []
        self.globals_watch = []          # [(va, source text)]
        self.guest_threads = []
        self.fields = None               # SendTableIndex once scanned
        self._field_thread = None
        self.index = None                # FunctionIndex once scanned
        self.func_display = {}           # va -> decorated list label
        self._xbe_hdr = None
        self._entry_va = None
        self._eip = None
        self._dbg_poll_id = None
        self.follow_eip = tk.BooleanVar(value=True)

        # Live update. The interval is a string var so the Spinbox can be typed
        # into; _live_ms() is the only thing that reads it, and it clamps.
        self.live_on = tk.BooleanVar(value=True)
        self.live_regs = tk.BooleanVar(value=True)
        self.live_interval = tk.StringVar(value="100")
        self.sampled = False             # registers came from a running guest
        self.patches = {}                # va -> original bytes
        self._live_id = None
        self._live_busy = False
        self._code_key = None            # what the code view last rendered
        self._sample_times = []

        self._load_live_settings()
        self._build()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._pump()
        self._debug_poll()
        self._restart_live()
        self.after(50, self.rescan)
        if address:
            self.goto(address)

    def _on_close(self):
        """Detach cleanly so no breakpoints are left armed in the guest."""
        self.live_on.set(False)
        self._save_live_settings()
        if self._live_id is not None:
            try:
                self.after_cancel(self._live_id)
            except Exception:
                pass
            self._live_id = None
        try:
            if self.session is not None:
                gdb_broker(self).release(self)
        except Exception:
            pass
        self.destroy()

    # ---- layout ----------------------------------------------------------
    def _build(self):
        bar = tk.Frame(self, bg="#212121")
        bar.pack(fill="x", padx=8, pady=6)
        tk.Label(bar, text="Address:", fg="#E0E0E0", bg="#212121",
                 font=("Helvetica", 9)).pack(side="left")
        self.addr_var = tk.StringVar(value="0x00011000")
        e = tk.Entry(bar, textvariable=self.addr_var, width=14, bd=0,
                     bg="#424242", fg="#00FF88", insertbackground="white",
                     font=("Courier", 10))
        e.pack(side="left", padx=4)
        e.bind("<Return>", lambda ev: self.goto_entry())
        tk.Button(bar, text="Go", command=self.goto_entry, bd=0,
                  bg="#FF9800", fg="black", font=("Helvetica", 8, "bold"),
                  padx=10).pack(side="left", padx=2)
        tk.Button(bar, text="\u2190 Back", command=self.back, bd=0,
                  bg="#546E7A", fg="white", font=("Helvetica", 8, "bold"),
                  padx=10).pack(side="left", padx=2)
        tk.Button(bar, text="Rescan functions", command=self.rescan, bd=0,
                  bg="#00897B", fg="white", font=("Helvetica", 8, "bold"),
                  padx=10).pack(side="left", padx=12)
        tk.Button(bar, text="Scan field names", command=self.scan_fields, bd=0,
                  bg="#6A1B9A", fg="white", font=("Helvetica", 8, "bold"),
                  padx=10).pack(side="left", padx=2)
        tk.Button(bar, text="Import symbols...", command=self.import_symbols,
                  bd=0, bg="#283593", fg="white",
                  font=("Helvetica", 8, "bold"),
                  padx=10).pack(side="left", padx=2)
        tk.Checkbutton(bar, text="Follow EIP", variable=self.follow_eip,
                       bg="#212121", fg="#E0E0E0", selectcolor="#424242",
                       activebackground="#212121", activeforeground="#FFFFFF",
                       font=("Helvetica", 8)).pack(side="left", padx=6)
        self.status = tk.Label(bar, text="", fg="#B0BEC5", bg="#212121",
                               font=("Helvetica", 8))
        self.status.pack(side="left", padx=8)

        self._build_debug_bar(self)

        # Code above, debugger panels below, both resizable - the panels are
        # useless squeezed to two rows and the code view is useless at 200px.
        vsplit = tk.PanedWindow(self, orient="vertical", bg="#111111",
                                sashwidth=6, sashrelief="raised", bd=0,
                                showhandle=False)
        vsplit.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        pane = tk.PanedWindow(vsplit, orient="horizontal", bg="#212121",
                              sashwidth=4, bd=0)
        vsplit.add(pane, minsize=200, stretch="always")

        left = tk.Frame(pane, bg="#212121")
        pane.add(left, minsize=240)
        fsearch = tk.Frame(left, bg="#212121")
        fsearch.pack(fill="x")
        self.fsearch_var = tk.StringVar()
        tk.Entry(fsearch, textvariable=self.fsearch_var, bd=0, bg="#424242",
                 fg="#FFFFFF", insertbackground="white",
                 font=("Helvetica", 9)).pack(fill="x", padx=2, pady=2)
        self.fsearch_var.trace_add("write", lambda *a: self._refilter())
        # A prologue scan of a 6 MB .text finds tens of thousands of functions,
        # most of them sub_ADDRESS. The filter is how you get back to the ones
        # with real names.
        frow = tk.Frame(left, bg="#212121")
        frow.pack(fill="x")
        tk.Label(frow, text="Show:", fg="#B0BEC5", bg="#212121",
                 font=("Helvetica", 8)).pack(side="left", padx=(2, 2))
        self.fsource_var = tk.StringVar(value="All")
        FSOURCES = ("All", "Named only", "Symbols", "RTTI", "Detected")
        fm = tk.OptionMenu(frow, self.fsource_var, *FSOURCES)
        fm.config(font=("Helvetica", 8), bg="#424242", fg="#E0E0E0", bd=0,
                  highlightthickness=0)
        fm.pack(side="left")
        self.fsource_var.trace_add("write", lambda *a: self._refilter())
        bind_wheel_cycle(fm, list(FSOURCES), self.fsource_var.get,
                         self.fsource_var.set)
        self.fcount = tk.Label(frow, text="", fg="#78909C", bg="#212121",
                               font=("Helvetica", 8))
        self.fcount.pack(side="right", padx=4)
        self.flist = tk.Listbox(left, bg="#151515", fg="#FFD54F",
                                font=("Courier", 9), selectbackground="#37474F",
                                exportselection=False, activestyle="none")
        fsb = ttk.Scrollbar(left, orient="vertical", command=self.flist.yview)
        self.flist.configure(yscrollcommand=fsb.set)
        self.flist.pack(side="left", fill="both", expand=True)
        fsb.pack(side="right", fill="y")
        self.flist.bind("<<ListboxSelect>>", self._on_pick_function)
        bind_wheel(self.flist, lambda d: self.flist.yview_scroll(d * 3, "units"))

        right = tk.Frame(pane, bg="#212121")
        pane.add(right, minsize=520, stretch="always")
        self.code = ttk.Treeview(right,
                                 columns=("mark", "addr", "bytes", "asm"),
                                 show="headings", selectmode="browse")
        for c, t, w in (("mark", "", 34), ("addr", "Address", 100),
                        ("bytes", "Bytes", 190), ("asm", "Instruction", 420)):
            self.code.heading(c, text=t)
            self.code.column(c, width=w,
                             anchor="center" if c == "mark" else "w",
                             stretch=(c == "asm"))
        csb = ttk.Scrollbar(right, orient="vertical", command=self._scroll)
        self.code.configure(yscrollcommand=None)
        self.code.pack(side="left", fill="both", expand=True)
        csb.pack(side="right", fill="y")
        self.scrollbar = csb
        bind_wheel(self.code, lambda d: self._scroll("scroll", d * 3, "units"))
        self.code.bind("<Double-Button-1>", self._follow)
        self.code.bind("<Configure>", lambda ev: self.render())
        self.code.bind("<Button-3>", self._menu)
        for seq, delta in (("<Down>", 1), ("<Up>", -1)):
            self.code.bind(seq, lambda ev, d=delta: self._scroll("scroll", d,
                                                                 "units"))
        self.code.bind("<Next>", lambda ev: self._scroll(
            "scroll", self.visible_rows(), "units"))
        self.code.bind("<Prior>", lambda ev: self._scroll(
            "scroll", -self.visible_rows(), "units"))
        self.code.tag_configure("call", foreground="#82B1FF")
        self.code.tag_configure("flow", foreground="#FFAB91")
        self.code.tag_configure("plain", foreground="#C5E1A5")
        # Breakpoint and current-instruction rows have to be obvious at a
        # glance, so they override the syntax colours rather than adding to
        # them - a red row is a breakpoint whatever the instruction is.
        self.code.tag_configure("bp", background="#5D1A1A", foreground="#FFCDD2")
        self.code.tag_configure("eip", background="#1B4D3E", foreground="#B9F6CA")
        self.code.tag_configure("bpeip", background="#5D1A1A",
                                foreground="#FFF59D")
        self.code.tag_configure("patched", background="#4A3B00",
                                foreground="#FFE082")
        self.code.bind("<F9>", lambda ev: (self._toggle_bp_here(), "break")[1])

        panels = tk.Frame(vsplit, bg="#212121")
        vsplit.add(panels, minsize=170)
        self._build_debug_panels(panels)

    # ---- reading ---------------------------------------------------------
    def _read(self, va, n):
        """Read guest memory at a virtual address, tolerating short reads."""
        pm = self.engine.ensure_pagemap()
        if pm is None:
            return b""
        out = bytearray()
        while n > 0:
            pa = pm.to_phys(va)
            if pa is None:
                break
            step = min(n, 0x1000 - (va & 0xFFF))
            chunk = self.engine.read_mem(self.engine.xbox_ram_base + pa, step)
            if not chunk:
                break
            out += chunk
            va += step
            n -= step
        return bytes(out)

    # ---- function scan ---------------------------------------------------
    def rescan(self):
        if self._scan_thread and self._scan_thread.is_alive():
            return
        self.status.config(text="Scanning for functions...", fg="#FF9800")
        self._scan_thread = threading.Thread(target=self._scan, daemon=True)
        self._scan_thread.start()

    def _scan(self):
        """
        Build the function list from every source, on a worker thread.

        RTTI runs first because it also establishes the section layout that
        everything else needs, but it is merged in last so its real class names
        win over the sub_ADDRESS names the code scan produces for the same
        addresses.
        """
        try:
            rtti = self._scan_rtti()
            idx = FunctionIndex()
            if self.sections:
                idx.scan(self._read, self.sections, image=self.image,
                         entry=self._entry_va, header=self._xbe_hdr,
                         progress=lambda m: self.inbox.put(("scanprogress", m)))
            idx.merge_rtti(rtti)
            if not idx.names and rtti:
                # No section layout, so only RTTI had anything to say.
                for va, name in rtti:
                    idx.add(va, name, "rtti")
        except Exception as e:
            import traceback
            tb = traceback.format_exc().strip().splitlines()
            where = tb[-2].strip() if len(tb) > 1 else ""
            self.inbox.put(("error", f"Scan failed: {e}   [{where}]"))
            return
        self.inbox.put(("index", idx))

    def import_symbols(self):
        """Load a .map / .sym / "address name" file over the scanned list."""
        path = filedialog.askopenfilename(
            title="Import symbols",
            filetypes=[("Symbol files", "*.map *.sym *.txt *.symbols"),
                       ("All files", "*.*")])
        if not path:
            return
        if self.index is None:
            self.index = FunctionIndex()
        try:
            n, desc = self.index.load_symbols(path, image=self.image)
        except OSError as exc:
            self.status.config(text=f"Could not read that file: {exc}",
                               fg="#f44336")
            return
        self.funcs = self.index.plain()
        self.func_display = dict(self.index.entries())
        self._refilter()
        self.render()
        self.status.config(text=desc, fg="#90CAF9" if n else "#FF9800")

    def _scan_rtti(self):
        """Recover Class::vtable[n] names for every vtable found in .rdata."""
        eng = self.engine
        ram = eng.xbox_ram_size_mb * 1024 * 1024
        pm = eng.ensure_pagemap()
        if pm is None:
            return []
        # Section bounds straight from the loaded header.
        xbe_phys = None
        for off in range(0, min(ram, 0x02000000), 0x1000):
            if eng.read_mem(eng.xbox_ram_base + off, 4) == b"XBEH":
                xbe_phys = off
                break
        if xbe_phys is None:
            return []
        img_lo, img_hi, text_lo, text_hi, rdata = self._sections(xbe_phys)
        if rdata is None:
            return []
        rlo, rhi = rdata
        data = self._read(rlo, min(rhi - rlo, 0x400000))
        funcs = {}
        for i in range(0, len(data) - 4, 4):
            loc = int.from_bytes(data[i:i + 4], "little")
            if not (rlo <= loc < rhi):
                continue
            vt = rlo + i + 4                      # vtable starts after locator
            first = int.from_bytes(data[i + 4:i + 8], "little") \
                if i + 8 <= len(data) else 0
            if not (text_lo <= first < text_hi):
                continue
            name = self._rtti_name(loc, text_lo, text_hi, rlo, rhi)
            if not name:
                continue
            j = 0
            while i + 4 + j * 4 + 4 <= len(data):
                fn = int.from_bytes(data[i + 4 + j * 4:i + 8 + j * 4], "little")
                if not (text_lo <= fn < text_hi):
                    break
                funcs.setdefault(fn, f"{name}::vtable[{j}]")
                j += 1
                if j > 400:
                    break
        return sorted(funcs.items())

    def _sections(self, xbe_phys):
        eng = self.engine
        def rd(off, n):
            return eng.read_mem(eng.xbox_ram_base + off, n)
        hdr = rd(xbe_phys, 0x200)
        # Kept for the function scan: the entry point and the debug-info
        # pointers live here, and the loader has already decrypted both.
        self._xbe_hdr = hdr
        try:
            self._entry_va = struct.unpack_from("<I", hdr, 0x128)[0]
        except struct.error:
            self._entry_va = None
        base = struct.unpack_from("<I", hdr, 0x104)[0]
        nsec = struct.unpack_from("<I", hdr, 0x11C)[0]
        secva = struct.unpack_from("<I", hdr, 0x120)[0]
        text = rdata = data = None
        img_lo = base
        img_hi = base + struct.unpack_from("<I", hdr, 0x10C)[0]
        for i in range(min(nsec, 32)):
            raw = self._read(secva + i * 0x38, 0x38)
            if len(raw) < 0x38:
                continue
            vaddr, vsize = struct.unpack_from("<II", raw, 4)
            namep = struct.unpack_from("<I", raw, 0x14)[0]
            nm = self._read(namep, 12).split(b"\0")[0]
            if nm == b".text":
                text = (vaddr, vaddr + vsize)
            elif nm == b".rdata":
                rdata = (vaddr, vaddr + vsize)
            elif nm == b".data":
                data = (vaddr, vaddr + vsize)
        if text is None:
            text = (img_lo, img_hi)
        # Remember the layout for the debugger panels, which annotate a dword
        # with the section it points into.
        secs = {}
        if text:
            secs[".text"] = text
        if rdata:
            secs[".rdata"] = rdata
        if data:
            secs[".data"] = data
        self.sections = secs
        self.image = (img_lo, img_hi)
        return img_lo, img_hi, text[0], text[1], rdata

    def _rtti_name(self, loc, text_lo, text_hi, rlo, rhi):
        td = self._read(loc + 0x0C, 4)
        if len(td) < 4:
            return None
        td = int.from_bytes(td, "little")
        raw = self._read(td + 8, 64)
        if not raw:
            return None
        nm = raw.split(b"\0")[0]
        if not nm.startswith(b".?AV") or not nm.endswith(b"@@"):
            return None
        try:
            return nm[4:-2].decode("ascii")
        except UnicodeDecodeError:
            return None

    # ---- Source field names ---------------------------------------------
    def scan_fields(self):
        """Recover networked field names from the title's SendTables."""
        if self._field_thread is not None and self._field_thread.is_alive():
            return
        if not self.sections:
            self.status.config(
                text="Rescan functions first - the section layout comes from "
                     "the XBE header", fg="#FF9800")
            return
        self.status.config(text="Scanning SendTables...", fg="#CE93D8")

        def work():
            try:
                idx = SendTableIndex().scan(
                    self._read, self.sections,
                    progress=lambda m: self.inbox.put(("fieldprogress", m)))
            except Exception as exc:                    # noqa: BLE001
                self.inbox.put(("error", f"Field scan failed: {exc}"))
                return
            self.inbox.put(("fields", idx))

        self._field_thread = threading.Thread(target=work, daemon=True)
        self._field_thread.start()

    def _class_context(self, va):
        """The RTTI class name of the function containing an address."""
        name = self._nearest_name(va)
        if not name or "::" not in name:
            return None
        return name.split("::", 1)[0]

    # Struct access through a register: [esi + 0x430], [ecx+8], [eax + esi*4 + 0x10].
    # An absolute [0x005FE4B0] is a global, not a field, so a bare hex operand
    # with no register must not be annotated as one.
    FIELD_OPERAND = re.compile(
        r"\[\s*e(?:ax|bx|cx|dx|si|di|bp|sp)\b[^\]]*?\+\s*(0x[0-9a-fA-F]+)\s*\]")

    def _annotate_fields(self, op_str, cls):
        """Field-name comment for the memory operands in one instruction."""
        if not self.fields or not self.fields.flat:
            return ""
        seen, out = set(), []
        for tok in self.FIELD_OPERAND.findall(op_str):
            off = int(tok, 16)
            if off in seen:
                continue
            seen.add(off)
            hit = self.fields.lookup(off, cls)
            if hit:
                out.append(f"{tok}={hit}")
        return "  ; " + "; ".join(out) if out else ""

    # ---- navigation ------------------------------------------------------
    def goto_entry(self):
        try:
            self.goto(int(self.addr_var.get().strip(), 16))
        except ValueError:
            self.status.config(text="Address must be hex", fg="#f44336")

    def goto(self, va, push=True):
        if push and self.top_va is not None:
            self.history.append(self.top_va)
        self.top_va = va
        self.addr_var.set(f"0x{va:08X}")
        self.render()

    def back(self):
        if self.history:
            self.goto(self.history.pop(), push=False)

    def _scroll(self, *args):
        if self.top_va is None:
            return
        if args[0] == "scroll":
            n = int(args[1])
            # Instructions are variable length, so "up" has no exact answer.
            # Stepping back 3 bytes per row and re-syncing is what every
            # disassembler does; forward uses real instruction lengths.
            if n < 0:
                self.goto(max(0, self.top_va + n * 3), push=False)
            else:
                rows = self._rows[:max(1, n)]
                self.goto(rows[-1][0] + rows[-1][1] if rows
                          else self.top_va + n, push=False)
        elif args[0] == "moveto":
            pass
        return "break"

    def visible_rows(self):
        try:
            h = self.code.winfo_height()
            rh = int(ttk.Style().lookup("Treeview", "rowheight") or 20)
        except Exception:
            h, rh = 400, 20
        return max(4, min(self.ROW_CAP, (h - rh) // max(1, rh)))

    def render(self):
        if self.top_va is None:
            return
        n = self.visible_rows()
        data = self._read(self.top_va, n * 8 + 32)
        # Every render rebuilds the tree, which drops the selection - and the
        # selection is how the breakpoint and run-to-here commands know which
        # instruction the user means. Toggling a breakpoint re-renders, so
        # without this F9 works once and then reports "select an instruction
        # first" for the same row that is still visibly highlighted.
        keep = None
        sel = self.code.selection()
        if sel:
            try:
                keep = int(str(self.code.item(sel[0], "values")[1]), 16)
            except (ValueError, IndexError):
                keep = None
        self.code.delete(*self.code.get_children())
        self._rows = []
        if not data:
            self.code.insert("", "end",
                             values=("", f"0x{self.top_va:08X}", "",
                                     "(not mapped - is a game running?)"))
            return
        try:
            import capstone
        except ImportError:
            self.code.insert("", "end",
                             values=("", "", "", "capstone is required: "
                                                "pip install capstone"))
            return
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        names = dict(self.funcs)
        bps = {bp.addr: bp for bp in self.breakpoints if bp.kind == "execute"}
        cls = self._class_context(self.top_va) if self.fields else None
        for ins in md.disasm(data, self.top_va):
            if len(self._rows) >= n:
                break
            text = f"{ins.mnemonic} {ins.op_str}".strip()
            tag = "plain"
            if ins.mnemonic.startswith("call"):
                tag = "call"
            elif ins.mnemonic.startswith(("j", "ret", "loop")):
                tag = "flow"
            text += self._annotate_fields(ins.op_str, cls)
            # Annotate a call/jump whose target we have a name for.
            for tok in ins.op_str.split():
                if tok.startswith("0x"):
                    try:
                        t = int(tok, 16)
                    except ValueError:
                        continue
                    if t in names:
                        text += f"        ; {names[t]}"
                    break
            label = names.get(ins.address)
            if label:
                self.code.insert("", "end",
                                 values=("", "", "", f"---- {label} ----"),
                                 tags=("flow",))
            bp = bps.get(ins.address)
            is_eip = (self._eip == ins.address)
            # A sampled EIP is a snapshot from a running guest, so it gets a
            # hollow marker - a filled one would claim the guest is stopped
            # there, which it is not.
            eip_mark = "\u25b7" if self.sampled and not (
                self.session is not None and self.session.stopped) else "\u25b6"
            mark = (eip_mark if is_eip and bp is None else
                    "\u25cf" + eip_mark if is_eip else
                    "\u25cf" if bp is not None and bp.enabled else
                    "\u25cb" if bp is not None else "")
            if ins.address in self.patches:
                mark += "\u2731"

            if bp is not None and bp.enabled:
                tag = "bpeip" if is_eip else "bp"
            elif is_eip:
                tag = "eip"
            elif ins.address in self.patches:
                tag = "patched"
            iid = self.code.insert("", "end",
                                   values=(mark, f"0x{ins.address:08X}",
                                           ins.bytes.hex(" "), text),
                                   tags=(tag,))
            if keep is not None and ins.address == keep:
                self.code.selection_set(iid)
            self._rows.append((ins.address, ins.size))

    def _follow(self, event=None):
        sel = self.code.selection()
        if not sel:
            return
        vals = self.code.item(sel[0], "values")
        for tok in str(vals[3]).split():
            if tok.startswith("0x"):
                try:
                    self.goto(int(tok, 16))
                except ValueError:
                    pass
                return "break"

    def _menu(self, event):
        item = self.code.identify_row(event.y)
        if item:
            self.code.selection_set(item)
        vals = self.code.item(item, "values") if item else ("", "", "", "")
        m = tk.Menu(self, tearoff=0, bg="#424242", fg="#FFFFFF",
                    activebackground="#FF9800", activeforeground="#000000")
        m.add_command(label="Follow target", command=self._follow)
        m.add_command(label="Copy line",
                      command=lambda: (self.clipboard_clear(),
                                       self.clipboard_append("  ".join(vals))))
        if vals and vals[1]:
            try:
                va = int(vals[1], 16)
            except ValueError:
                va = None
            if va is not None:
                nbytes = len(str(vals[2]).split())
                existing = self._find_exec_bp(va)
                m.add_separator()
                m.add_command(
                    label=("Remove execute breakpoint (F9)" if existing
                           else "Set execute breakpoint (F9)"),
                    command=lambda a=va: self._toggle_bp_here(a))
                m.add_command(label="Breakpoint here...",
                              command=lambda a=va: self._bp_dialog(addr=a))
                m.add_command(label="Break on write to this address...",
                              command=lambda a=va: self._bp_dialog(
                                  addr=a, kind="write"))
                m.add_command(label="Run to here",
                              command=self._run_to_here)
                m.add_command(label="Set EIP here",
                              command=self._set_eip_here)
                m.add_separator()
                m.add_command(label="NOP this instruction now (writes RAM)",
                              command=lambda a=va: self._nop_here(a))
                m.add_command(label="Patch bytes...",
                              command=lambda a=va: self._patch_bytes_dialog(a))
                if va in self.patches:
                    m.add_command(label="Undo this patch",
                                  command=lambda a=va: self._undo_patch(a))
                if self.patches:
                    m.add_command(
                        label=f"Undo all {len(self.patches)} patch(es)",
                        command=self._undo_all_patches)
                m.add_separator()
                m.add_command(
                    label=f"Copy NOP code for these {nbytes} byte(s)",
                    command=lambda a=va, k=nbytes: self._copy_nop(a, k))
                m.add_command(
                    label="Open in Memory Viewer",
                    command=lambda a=va: self.master.open_mem_viewer(
                        a, virtual=True))
        popup_menu(m, event.x_root, event.y_root)
        return "break"

    def _copy_nop(self, va, nbytes):
        """Emit type-8 writes that NOP out the selected instruction."""
        lines = [f"8{va + i:07X} 00000090" for i in range(nbytes)]
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))
        self.status.config(text=f"Copied {nbytes} NOP line(s)", fg="#4CAF50")

    # ---- function list ---------------------------------------------------
    def _refilter(self):
        needle = self.fsearch_var.get().strip().lower()
        want = self.fsource_var.get()
        src = self.index.source if self.index is not None else {}
        keep = {"Symbols": ("symbol",), "RTTI": ("rtti",),
                "Detected": ("call", "prologue", "string", "entry")}.get(want)
        self.filtered = []
        for a, n in self.funcs:
            if keep is not None and src.get(a) not in keep:
                continue
            if want == "Named only" and n.startswith("sub_"):
                continue
            label = self.func_display.get(a, n)
            if needle and needle not in label.lower() \
                    and needle not in f"{a:08x}":
                continue
            self.filtered.append((a, label))
        self.flist.delete(0, tk.END)
        # No cap. The old 5000-entry limit silently hid the tail of the list -
        # 11,758 functions meant the last 6,758 simply were not there, which
        # reads as "cannot scroll to the bottom". A single insert() with all
        # the rows is also far faster than inserting them one at a time.
        if self.filtered:
            self.flist.insert(tk.END,
                              *[f"{a:08X}  {n}" for a, n in self.filtered])
        self.fcount.config(text=f"{len(self.filtered)} / {len(self.funcs)}")

    def _on_pick_function(self, event=None):
        sel = self.flist.curselection()
        if not sel or sel[0] >= len(self.filtered):
            return
        self.goto(self.filtered[sel[0]][0])


    # ======================================================================
    # DEBUGGER
    # ======================================================================
    # Run control, breakpoints and the state panels. All of it needs xemu's
    # guest gdbstub, which is started from xemu's Monitor with "gdbserver"
    # (and stopped again with "gdbserver none"). Without it the window is
    # still a working disassembler; every debug control simply says so.

    DBG_TABS = ("Registers", "Breakpoints", "Stack", "Threads", "Locals",
                "Parameters", "Globals")

    def _build_debug_bar(self, parent):
        bar = tk.Frame(parent, bg="#1A1A1A")
        bar.pack(fill="x", padx=8, pady=(0, 4))

        self.break_on_attach = tk.BooleanVar(value=False)
        self.btn_attach = tk.Button(bar, text="Attach", command=self._toggle_attach,
                                    bd=0, bg="#4CAF50", fg="white", padx=10,
                                    font=("Helvetica", 8, "bold"))
        self.btn_attach.pack(side="left", padx=2, pady=3)

        tk.Label(bar, text="Host:", fg="#B0BEC5", bg="#1A1A1A",
                 font=("Helvetica", 8)).pack(side="left", padx=(6, 1))
        self.dbg_host = tk.StringVar(value=GDB_DEFAULT_HOST)
        tk.Entry(bar, textvariable=self.dbg_host, width=11, bd=0, bg="#424242",
                 fg="white", insertbackground="white",
                 font=("Courier", 8)).pack(side="left")
        tk.Label(bar, text="Port:", fg="#B0BEC5", bg="#1A1A1A",
                 font=("Helvetica", 8)).pack(side="left", padx=(6, 1))
        self.dbg_port = tk.StringVar(value=str(GDB_DEFAULT_PORT))
        tk.Entry(bar, textvariable=self.dbg_port, width=6, bd=0, bg="#424242",
                 fg="white", insertbackground="white",
                 font=("Courier", 8)).pack(side="left")
        tk.Checkbutton(bar, text="Break on attach", variable=self.break_on_attach,
                       bg="#1A1A1A", fg="#E0E0E0", selectcolor="#424242",
                       activebackground="#1A1A1A", activeforeground="#FFFFFF",
                       font=("Helvetica", 8)).pack(side="left", padx=(8, 0))

        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y",
                                                   padx=8, pady=4)
        # Keyboard shortcuts match PCSX2 / Visual Studio, which is what anyone
        # coming from either will try first.
        for attr, text, cmd in (
                ("btn_break", "Break", self._dbg_break),
                ("btn_run", "Run (F5)", self._dbg_run),
                ("btn_step_into", "Step Into (F11)", self._dbg_step_into),
                ("btn_step_over", "Step Over (F10)", self._dbg_step_over),
                ("btn_step_out", "Step Out (Shift+F11)", self._dbg_step_out)):
            b = tk.Button(bar, text=text, command=cmd, bd=0, bg="#37474F",
                          fg="white", padx=8, state="disabled",
                          font=("Helvetica", 8, "bold"))
            b.pack(side="left", padx=2, pady=3)
            setattr(self, attr, b)

        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y",
                                                   padx=8, pady=4)
        tk.Button(bar, text="Protocol log", command=self._show_trace, bd=0,
                  bg="#455A64", fg="white", padx=8,
                  font=("Helvetica", 8, "bold")).pack(side="left", padx=2)
        tk.Button(bar, text="Go to EIP", command=self._goto_eip, bd=0,
                  bg="#5D4037", fg="white", padx=8,
                  font=("Helvetica", 8, "bold")).pack(side="left", padx=2)
        tk.Button(bar, text="Add Breakpoint...", command=self._bp_dialog, bd=0,
                  bg="#B71C1C", fg="white", padx=8,
                  font=("Helvetica", 8, "bold")).pack(side="left", padx=2)

        self._build_live_controls(bar)

        self.dbg_state = tk.Label(bar, text="stub not attached", fg="#78909C",
                                  bg="#1A1A1A", font=("Helvetica", 8, "bold"))
        self.dbg_state.pack(side="right", padx=8)

        # bind() on the Toplevel, not bind_all() - bind_all is application
        # wide, so F5 pressed in the main scanner window would step the guest.
        # Key events propagate from the focused child up to here, which is
        # exactly the "while this window has focus" scope wanted.
        for seq, fn in (("<F5>", self._dbg_run), ("<F9>", self._toggle_bp_here),
                        ("<F10>", self._dbg_step_over),
                        ("<F11>", self._dbg_step_into),
                        ("<Shift-F11>", self._dbg_step_out),
                        ("<Pause>", self._dbg_break)):
            self.bind(seq, lambda ev, f=fn: (f(), "break")[1])

    # ---- panels ----------------------------------------------------------
    def _build_debug_panels(self, parent):
        nb = ttk.Notebook(parent)
        nb.pack(fill="both", expand=True)
        self.dbg_nb = nb
        self.dbg_trees = {}
        for name in self.DBG_TABS:
            frame = tk.Frame(nb, bg="#212121")
            nb.add(frame, text=name)
            getattr(self, f"_tab_{name.lower()}")(frame)

    def _make_tree(self, parent, cols, key, height=6):
        """A dark Treeview with a scrollbar, registered under key."""
        wrap = tk.Frame(parent, bg="#212121")
        wrap.pack(fill="both", expand=True)
        tree = ttk.Treeview(wrap, columns=[c[0] for c in cols],
                            show="headings", height=height)
        for cid, text, width, anchor in cols:
            tree.heading(cid, text=text)
            tree.column(cid, width=width, anchor=anchor)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        bind_wheel(tree, lambda d, t=tree: t.yview_scroll(d * 3, "units"))
        tree.tag_configure("dim", foreground="#616161")
        tree.tag_configure("hot", foreground="#FF8A65")
        tree.tag_configure("ok", foreground="#AED581")
        self.dbg_trees[key] = tree
        return tree

    def _tab_registers(self, f):
        t = self._make_tree(f, (("reg", "Register", 90, "w"),
                                ("hex", "Hex", 110, "w"),
                                ("dec", "Signed", 130, "e"),
                                ("note", "Points at", 300, "w")), "regs")
        t.bind("<Double-Button-1>", self._edit_register)
        tk.Label(f, text="Double-click a register to change it while halted.",
                 fg="#78909C", bg="#212121",
                 font=("Helvetica", 8)).pack(anchor="w", padx=4)

    def _tab_breakpoints(self, f):
        btns = tk.Frame(f, bg="#212121")
        btns.pack(fill="x")
        for text, cmd, bg in (("Add...", self._bp_dialog, "#B71C1C"),
                              ("Edit...", self._bp_edit_selected, "#455A64"),
                              ("Enable / Disable", self._bp_toggle_selected,
                               "#00695C"),
                              ("Delete", self._bp_delete_selected, "#616161"),
                              ("Delete All", self._bp_delete_all, "#424242")):
            tk.Button(btns, text=text, command=cmd, bd=0, bg=bg, fg="white",
                      padx=8, font=("Helvetica", 8, "bold")
                      ).pack(side="left", padx=2, pady=3)
        t = self._make_tree(f, (("on", "On", 34, "center"),
                                ("kind", "Type", 70, "center"),
                                ("addr", "Address", 100, "w"),
                                ("size", "Size", 44, "center"),
                                ("cond", "Condition", 260, "w"),
                                ("hits", "Hits", 50, "center"),
                                ("skip", "Skipped", 60, "center"),
                                ("label", "Note", 200, "w")), "bps")
        t.bind("<Double-Button-1>", lambda ev: self._bp_edit_selected())

    def _tab_stack(self, f):
        split = tk.Frame(f, bg="#212121")
        split.pack(fill="both", expand=True)
        left = tk.Frame(split, bg="#212121")
        left.pack(side="left", fill="both", expand=True)
        tk.Label(left, text="Call stack (EBP chain)", fg="#FFD54F",
                 bg="#212121", font=("Helvetica", 8, "bold")).pack(anchor="w")
        t = self._make_tree(left, (("n", "#", 30, "center"),
                                   ("ret", "Returns to", 100, "w"),
                                   ("fn", "Function", 240, "w"),
                                   ("ebp", "Frame", 100, "w")), "frames")
        t.bind("<Double-Button-1>", self._goto_frame)
        right = tk.Frame(split, bg="#212121")
        right.pack(side="left", fill="both", expand=True, padx=(6, 0))
        tk.Label(right, text="Raw stack from ESP", fg="#FFD54F", bg="#212121",
                 font=("Helvetica", 8, "bold")).pack(anchor="w")
        self._make_tree(right, (("addr", "Address", 100, "w"),
                                ("off", "Offset", 60, "e"),
                                ("val", "Value", 100, "w"),
                                ("note", "Meaning", 240, "w")), "stack")

    def _tab_threads(self, f):
        top = tk.Frame(f, bg="#212121")
        top.pack(fill="x")
        tk.Button(top, text="Scan for guest threads", command=self._scan_threads,
                  bd=0, bg="#00695C", fg="white", padx=8,
                  font=("Helvetica", 8, "bold")).pack(side="left", padx=2, pady=3)
        self.thread_note = tk.Label(
            top, text="The stub reports vCPUs, not Xbox threads - scanning "
                      "finds KTHREAD objects (heuristic, see the Note column).",
            fg="#78909C", bg="#212121", font=("Helvetica", 8))
        self.thread_note.pack(side="left", padx=8)
        self._make_tree(f, (("id", "Thread", 90, "w"),
                            ("src", "Source", 70, "center"),
                            ("state", "State", 90, "center"),
                            ("where", "KTHREAD / EIP", 110, "w"),
                            ("stack", "Stack range", 190, "w"),
                            ("note", "Note", 260, "w")), "threads")

    def _tab_locals(self, f):
        tk.Label(f, text="Frame dwords between ESP and EBP. Without debug "
                         "information these are unnamed slots, exactly as the "
                         "disassembly shows them.",
                 fg="#78909C", bg="#212121", font=("Helvetica", 8),
                 wraplength=900, justify="left").pack(anchor="w", padx=4)
        self._make_tree(f, (("slot", "Slot", 110, "w"),
                            ("addr", "Address", 100, "w"),
                            ("hex", "Hex", 100, "w"),
                            ("dec", "Signed", 110, "e"),
                            ("flt", "As float", 110, "e"),
                            ("note", "Points at", 260, "w")), "locals")

    def _tab_parameters(self, f):
        tk.Label(f, text="Stack arguments at [ebp+8] and up, plus ECX for a "
                         "thiscall. Argument count is unknown without a "
                         "prototype, so a fixed window is shown.",
                 fg="#78909C", bg="#212121", font=("Helvetica", 8),
                 wraplength=900, justify="left").pack(anchor="w", padx=4)
        self._make_tree(f, (("slot", "Slot", 110, "w"),
                            ("addr", "Address", 100, "w"),
                            ("hex", "Hex", 100, "w"),
                            ("dec", "Signed", 110, "e"),
                            ("flt", "As float", 110, "e"),
                            ("note", "Points at", 260, "w")), "params")

    def _tab_globals(self, f):
        btns = tk.Frame(f, bg="#212121")
        btns.pack(fill="x")
        for text, cmd, bg in (
                ("Fill from this function", self._globals_from_function,
                 "#00695C"),
                ("Add address...", self._globals_add, "#455A64"),
                ("Remove", self._globals_remove, "#616161"),
                ("Clear", self._globals_clear, "#424242"),
                ("Send to Address Table", self._globals_to_table, "#FF9800")):
            tk.Button(btns, text=text, command=cmd, bd=0, bg=bg,
                      fg="black" if bg == "#FF9800" else "white", padx=8,
                      font=("Helvetica", 8, "bold")
                      ).pack(side="left", padx=2, pady=3)
        t = self._make_tree(f, (("addr", "Address", 100, "w"),
                                ("sec", "Section", 80, "center"),
                                ("hex", "Hex", 100, "w"),
                                ("dec", "Signed", 110, "e"),
                                ("flt", "As float", 110, "e"),
                                ("src", "Referenced by", 300, "w")), "globals")
        t.bind("<Double-Button-1>", self._globals_open_viewer)

    # ---- attach / run control -------------------------------------------
    def _toggle_attach(self):
        if self.session is not None and self.session.connected:
            broker = gdb_broker(self)
            # Only take OUR breakpoints out; another window may still be
            # watching an address on the same connection.
            for bp in list(self.breakpoints):
                # force, and regardless of whether the session list knows about
                # it: after Detach nothing of ours may still be armed.
                self.session.disarm(bp, force=True)
                if bp in self.session.breakpoints:
                    self.session.breakpoints.remove(bp)
            try:
                self.session.force_resume()
            except Exception:                               # noqa: BLE001
                pass
            broker.release(self)
            self.session = None
            self._eip = None
            self.btn_attach.config(text="Attach", bg="#4CAF50")
            self._set_dbg_state("stub not attached", "#78909C")
            self._debug_buttons(False)
            self.render()
            self._refresh_debug_views()
            return
        try:
            port = int(self.dbg_port.get())
        except ValueError:
            self._set_dbg_state("port must be a number", "#f44336")
            return
        broker = gdb_broker(self)
        try:
            sess = broker.acquire(self, self.engine,
                                  host=self.dbg_host.get().strip(), port=port,
                                  read_fallback=self._read, label="Debugger",
                                  break_on_attach=self.break_on_attach.get())
            # Breakpoints live on the window, so they are re-armed on the
            # shared session whichever window connected it first.
            for bp in self.breakpoints:
                if bp not in sess.breakpoints:
                    sess.breakpoints.append(bp)
                bp.armed = False
                sess.arm(bp)
            broker.subscribe(self, self._handle_debug_event)
        except (GdbStubError, OSError) as exc:
            self._set_dbg_state(f"cannot attach: {exc}", "#f44336")
            self.status.config(
                text="Type 'gdbserver' in xemu's Monitor first", fg="#FF9800")
            return
        self.session = sess
        self.sampled = False
        self.btn_attach.config(text="Detach", bg="#C62828")
        if sess.stopped:
            self._eip = sess.regs.get("eip")
            self._set_dbg_state(
                f"attached - HALTED at 0x{self._eip or 0:08X} (press Run)",
                "#FFD54F")
        else:
            self._set_dbg_state("attached - running", "#4CAF50")
        self._debug_buttons(True)
        self._refresh_debug_views()

    def _debug_buttons(self, on):
        state = "normal" if on else "disabled"
        for attr in ("btn_break", "btn_run", "btn_step_into", "btn_step_over",
                     "btn_step_out"):
            getattr(self, attr).config(state=state)

    def _set_dbg_state(self, text, colour="#B0BEC5"):
        self.dbg_state.config(text=text, fg=colour)

    def _need_session(self):
        if self.session is None or not self.session.connected:
            self._set_dbg_state("attach to xemu's stub first", "#FF9800")
            return False
        return True

    def _need_halted(self):
        if not self._need_session():
            return False
        if not self.session.stopped:
            self._set_dbg_state("press Break first - the guest is running",
                                "#FF9800")
            return False
        return True

    def _dbg_break(self):
        if not self._need_session():
            return
        try:
            ev = self.session.interrupt()
        except (GdbStubError, OSError) as exc:
            self._set_dbg_state(f"stub error: {exc}", "#f44336")
            return
        if ev:
            self._handle_debug_event(*ev)
        else:
            self._set_dbg_state("break requested...", "#FF9800")

    def _dbg_run(self):
        if not self._need_session():
            return
        # Deliberately not _need_halted(): if our state tracking is wrong, Run
        # must still resume the emulator rather than refuse.
        self.session.force_resume()
        self._eip = None
        self._set_dbg_state("running", "#4CAF50")
        self.render()
        self._refresh_debug_views()

    def _dbg_step_into(self):
        if not self._need_halted():
            return
        self.session.step_into()

    def _dbg_step_over(self):
        if not self._need_halted():
            return
        self.session.step_over()

    def _dbg_step_out(self):
        if not self._need_halted():
            return
        err = self.session.step_out()
        if err:
            self._set_dbg_state(err, "#FF9800")

    def _show_trace(self):
        """
        Every packet in and out, newest last, with the gap between them.

        Here because remote-stub behaviour varies between builds in ways that
        cannot be reproduced from this end: whether an interrupt is answered,
        whether a stop reply names the watchpoint that fired, whether the
        continue was acknowledged. The timings matter as much as the packets -
        a two-second gap before a reply is a timeout, not a slow stub.
        """
        if self.session is None or self.session.client is None:
            self._set_dbg_state("attach first - there is nothing to log",
                                "#FF9800")
            return
        win = tk.Toplevel(self)
        win.title("gdb protocol log")
        win.geometry("820x520")
        win.configure(bg="#212121")
        txt = tk.Text(win, bg="#1A1A1A", fg="#E0E0E0", insertbackground="white",
                      font=("Courier", 9), wrap="none")
        sb = ttk.Scrollbar(win, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        txt.pack(side="left", fill="both", expand=True)
        entries = list(self.session.client.trace)
        prev = entries[0][0] if entries else 0
        for t, direction, data in entries:
            arrow = {">": "send", "<": "recv", "!": "note"}.get(direction,
                                                                direction)
            txt.insert("end", f"{(t - prev) * 1000:8.1f} ms  {arrow}  {data}\n")
            prev = t
        txt.see("end")

        def save():
            path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text", "*.txt"), ("All files", "*.*")])
            if path:
                with open(path, "w") as fh:
                    fh.write(txt.get("1.0", "end"))
        tk.Button(win, text="Save...", command=save, bd=0, bg="#455A64",
                  fg="white", font=("Helvetica", 9, "bold")).pack(
                      side="bottom", pady=4)

    def _goto_eip(self):
        if self._eip is not None:
            self.goto(self._eip)
        else:
            self._set_dbg_state("no current EIP - the guest is not halted",
                                "#FF9800")

    # ---- event handling --------------------------------------------------
    def _debug_poll(self):
        """
        Notice when the shared connection has gone away.

        Events no longer arrive through here: reading the socket is the
        broker's job and it dispatches to _handle_debug_event. Two readers on
        one stub connection is the bug this replaced.
        """
        try:
            if self.session is not None and not self.session.connected:
                # Try once to get it back before giving up. Losing the socket
                # for a moment should not cost the whole session.
                broker = gdb_broker(self)
                if broker.reconnect(self.engine, read_fallback=self._read):
                    self.session = broker.session
                    self._set_dbg_state(
                        "the connection dropped and was re-established",
                        "#FFD54F")
                else:
                    self._set_dbg_state(
                        "the stub connection closed - in xemu's Monitor: "
                        "gdbserver none, then gdbserver", "#f44336")
                    self.session = None
                    self.btn_attach.config(text="Attach", bg="#4CAF50")
                    self._debug_buttons(False)
        except Exception as exc:                      # noqa: BLE001
            self._set_dbg_state(f"debugger error: {exc}", "#f44336")
        if self.winfo_exists():
            self._dbg_poll_id = self.after(200, self._debug_poll)

    def _handle_debug_event(self, kind, payload):
        if kind == "stopped":
            eip = payload.get("eip", 0)
            self._eip = eip
            self.sampled = False
            self._code_key = None
            reason = payload.get("reason", "stopped")
            bp = payload.get("bp")
            if bp is not None and bp.label:
                reason += f" - {bp.label}"
            if payload.get("watch") is not None:
                reason += f" on 0x{payload['watch']:08X}"
            self._set_dbg_state(f"halted at 0x{eip:08X} ({reason})", "#FFD54F")
            if self.follow_eip.get() and not any(a == eip for a, _ in self._rows):
                # Only re-anchor the view when EIP has left it. Jumping to put
                # the current instruction on the top row at every single step
                # makes the code scroll under the cursor constantly, and
                # push=False keeps 200 single steps out of the Back history.
                self.goto(eip, push=False)
            else:
                self.render()
            self._refresh_debug_views()
        elif kind == "resumed":
            self._set_dbg_state(
                f"condition false at 0x{payload.addr:08X} - resumed "
                f"({payload.skipped} skipped)", "#78909C")
            self._refresh_bp_tree()
        elif kind == "exited":
            self._set_dbg_state("the guest stopped or the title exited",
                                "#f44336")
        elif kind == "error":
            self._set_dbg_state(str(payload), "#f44336")

    # ---- panel refresh ---------------------------------------------------
    def _clear_tree(self, key):
        t = self.dbg_trees.get(key)
        if t is not None:
            t.delete(*t.get_children())
        return t

    def _refresh_debug_views(self):
        self._refresh_bp_tree()
        halted = (self.session is not None and self.session.connected
                  and self.session.stopped)
        for key in ("regs", "frames", "stack", "locals", "params"):
            self._clear_tree(key)
        self._refresh_globals_tree()
        if not halted:
            t = self.dbg_trees.get("regs")
            if t is not None:
                t.insert("", "end", values=("", "", "",
                                            "halted state required"),
                         tags=("dim",))
            return
        self._refresh_registers()
        self._refresh_stack()
        self._refresh_slots("locals")
        self._refresh_slots("params")
        self._refresh_threads()

    def _describe_pointer(self, value):
        """One-line note for a dword: a known function, a section, or nothing."""
        if not value:
            return ""
        name = dict(self.funcs).get(value)
        if name:
            return name
        sec = self._section_of(value)
        return sec or ""

    def _section_of(self, va):
        for name, (lo, hi) in (self.sections or {}).items():
            if lo <= va < hi:
                return name
        if self.sections:
            lo = min(v[0] for v in self.sections.values())
            hi = max(v[1] for v in self.sections.values())
            if lo <= va < hi:
                return "image"
        if 0x80000000 <= va < 0x84000000:
            return "kernel"
        if 0xD0000000 <= va < 0xD0100000:
            return "kernel data"
        return ""

    @staticmethod
    def _as_float(value):
        if value is None:
            return ""
        try:
            f = struct.unpack("<f", struct.pack("<I", value & 0xFFFFFFFF))[0]
        except (struct.error, OverflowError):
            return ""
        if f != f or abs(f) in (float("inf"),):
            return ""
        if f != 0 and (abs(f) < 1e-6 or abs(f) > 1e12):
            return f"{f:.3e}"
        return f"{f:.4f}"

    @staticmethod
    def _signed(value):
        if value is None:
            return ""
        return str(value - 0x100000000 if value >= 0x80000000 else value)

    def _refresh_registers(self):
        t = self._clear_tree("regs")
        regs = self.session.regs
        for name in GDB_X86_REGS:
            if name not in regs:
                continue
            v = regs[name]
            note = self._describe_pointer(v)
            if name == "eflags":
                note = self._flags_text(v)
            t.insert("", "end", values=(name, f"0x{v:08X}", self._signed(v),
                                        note),
                     tags=("hot",) if name == "eip" else ())

    @staticmethod
    def _flags_text(v):
        names = ((0, "CF"), (2, "PF"), (4, "AF"), (6, "ZF"), (7, "SF"),
                 (8, "TF"), (9, "IF"), (10, "DF"), (11, "OF"))
        return " ".join(n for b, n in names if v & (1 << b))

    def _refresh_stack(self):
        t = self._clear_tree("frames")
        names = dict(self.funcs)
        img = self._in_image
        for i, (ebp, ret) in enumerate(self.session.call_stack(in_image=img)):
            t.insert("", "end", values=(i + 1, f"0x{ret:08X}",
                                        self._nearest_name(ret, names),
                                        f"0x{ebp:08X}"))
        t2 = self._clear_tree("stack")
        esp = self.session.regs.get("esp", 0)
        for addr, val in self.session.stack_words(48):
            t2.insert("", "end", values=(f"0x{addr:08X}", f"+0x{addr - esp:X}",
                                         f"0x{val:08X}",
                                         self._describe_pointer(val)))

    def _in_image(self, va):
        if self.image is None:
            return 0x00010000 <= va < 0x01000000
        return self.image[0] <= va < self.image[1]

    def _nearest_name(self, va, names=None):
        """
        Name the function a return address falls inside.

        Return addresses point after the call, i.e. into the middle of the
        caller, so an exact vtable-slot match almost never hits. The nearest
        known entry at or below the address is the best available answer.
        """
        names = names if names is not None else dict(self.funcs)
        if va in names:
            return names[va]
        best = None
        for a, n in self.funcs:
            if a <= va and (best is None or a > best[0]):
                best = (a, n)
        if best is None or va - best[0] > 0x4000:
            return ""
        return f"{best[1]} + 0x{va - best[0]:X}"

    def _refresh_slots(self, which):
        t = self._clear_tree(which)
        kind = "locals" if which == "locals" else "params"
        if kind == "params":
            ecx = self.session.regs.get("ecx")
            if ecx is not None:
                t.insert("", "end",
                         values=("ecx (this?)", "", f"0x{ecx:08X}",
                                 self._signed(ecx), "",
                                 self._describe_pointer(ecx)), tags=("dim",))
        for slot, addr, val in self.session.frame_slots(kind, 16):
            t.insert("", "end",
                     values=(slot, f"0x{addr:08X}",
                             "" if val is None else f"0x{val:08X}",
                             self._signed(val), self._as_float(val),
                             self._describe_pointer(val or 0)))

    def _refresh_threads(self):
        t = self._clear_tree("threads")
        if self.session is None or not self.session.connected:
            t.insert("", "end", values=("", "", "", "", "",
                                        "attach to the stub first"),
                     tags=("dim",))
            return
        eip = self.session.regs.get("eip")
        for tid, extra in self.session.stub_threads():
            t.insert("", "end",
                     values=(tid, "stub", "halted" if self.session.stopped
                             else "running",
                             f"0x{eip:08X}" if eip else "",
                             "", extra or "vCPU as reported by QEMU"),
                     tags=("ok",))
        # Re-test each scanned candidate against the current ESP rather
        # than trusting the flag from scan time - after a step or a thread
        # switch a different candidate owns the stack.
        for row in self.guest_threads:
            row["current"] = bool(eip is not None and row["stack_limit"]
                                  <= self.session.regs.get("esp", 0)
                                  < row["stack_base"])
            t.insert("", "end",
                     values=(f"0x{row['kthread']:08X}", "guest",
                             "running" if row["current"] else "?",
                             f"0x{row['kthread']:08X}",
                             f"0x{row['stack_limit']:08X}-"
                             f"0x{row['stack_base']:08X}",
                             ("current (stack contains ESP)" if row["current"]
                              else f"KTHREAD candidate, stack at +0x"
                                   f"{row['field_offset']:X}")),
                     tags=("ok",) if row["current"] else ("dim",))

    def _scan_threads(self):
        if not self._need_session():
            return
        if not self.session.stopped:
            self.thread_note.config(
                text="Break first - matching a thread against ESP needs a "
                     "halted guest.", fg="#FF9800")
            return
        self.thread_note.config(text="Scanning kernel memory...", fg="#FF9800")
        self.update_idletasks()

        def work():
            try:
                pm = self.engine.ensure_pagemap()
                rows = self.session.scan_guest_threads(pm)
            except Exception as exc:                  # noqa: BLE001
                self.inbox.put(("error", f"Thread scan failed: {exc}"))
                return
            self.inbox.put(("threads", rows))

        threading.Thread(target=work, daemon=True).start()

    # ---- breakpoint management ------------------------------------------
    def _refresh_bp_tree(self):
        t = self._clear_tree("bps")
        if t is None:
            return
        for bp in self.breakpoints:
            if not bp.error and not self._plausible_virtual(bp.addr):
                bp.error = ("not mapped as a virtual address - is this a "
                            "physical offset?")
            state = "on" if bp.enabled else "off"
            if bp.enabled and self.session is not None and not bp.armed \
                    and self.session.connected:
                state = "err"
            t.insert("", "end", iid=str(id(bp)),
                     values=(state, bp.kind, f"0x{bp.addr:08X}",
                             bp.size if bp.kind != "execute" else "",
                             bp.condition or "", bp.hits, bp.skipped,
                             bp.error or bp.label),
                     tags=("dim",) if not bp.enabled
                     else ("hot",) if bp.error else ())

    def _selected_bp(self):
        t = self.dbg_trees.get("bps")
        sel = t.selection() if t else ()
        if not sel:
            return None
        for bp in self.breakpoints:
            if str(id(bp)) == sel[0]:
                return bp
        return None

    def _add_bp(self, bp):
        # BOTH lists. The window's list owns the breakpoint across attach and
        # detach; the session's list is shared with any watch windows on the
        # same connection. They used to be the same list; keeping them in step
        # by hand is the price of one connection serving several windows.
        self.breakpoints.append(bp)
        if self.session is not None:
            self.session.add(bp)
        self._refresh_bp_tree()
        self.render()

    def _remove_bp(self, bp):
        if self.session is not None:
            self.session.remove(bp)
        if bp in self.breakpoints:
            self.breakpoints.remove(bp)
        self._refresh_bp_tree()
        self.render()

    def _find_exec_bp(self, addr):
        for bp in self.breakpoints:
            if bp.kind == "execute" and bp.addr == addr:
                return bp
        return None

    def _selected_code_addr(self):
        sel = self.code.selection()
        if not sel:
            return None
        vals = self.code.item(sel[0], "values")
        try:
            return int(str(vals[1]), 16)
        except (ValueError, IndexError):
            return None

    def _toggle_bp_here(self, addr=None):
        if addr is None:
            addr = self._selected_code_addr()
        if addr is None:
            self._set_dbg_state("select an instruction first", "#FF9800")
            return
        existing = self._find_exec_bp(addr)
        if existing is not None:
            self._remove_bp(existing)
            self._set_dbg_state(f"breakpoint removed at 0x{addr:08X}",
                                "#78909C")
        else:
            self._add_bp(Breakpoint(addr, "execute"))
            self._set_dbg_state(f"execute breakpoint at 0x{addr:08X}",
                                "#EF9A9A")

    def _bp_toggle_selected(self):
        bp = self._selected_bp()
        if bp is None:
            return
        if self.session is not None:
            self.session.set_enabled(bp, not bp.enabled)
        else:
            bp.enabled = not bp.enabled
        self._refresh_bp_tree()
        self.render()

    def _bp_delete_selected(self):
        bp = self._selected_bp()
        if bp is not None:
            self._remove_bp(bp)

    def _bp_delete_all(self):
        for bp in list(self.breakpoints):
            self._remove_bp(bp)

    def _bp_edit_selected(self):
        bp = self._selected_bp()
        if bp is not None:
            self._bp_dialog(bp=bp)

    def _plausible_virtual(self, va):
        """Is this address mapped in the guest's virtual space right now?"""
        pm = self.engine.ensure_pagemap()
        if pm is None:
            return True             # cannot tell; do not cry wolf
        try:
            return pm.to_phys(va) is not None
        except Exception:                                   # noqa: BLE001
            return True

    def _run_to_here(self):
        addr = self._selected_code_addr()
        if addr is None or not self._need_halted():
            return
        self.session.run_to(addr)
        self._eip = None
        self._set_dbg_state(f"running to 0x{addr:08X}", "#4CAF50")
        self.render()

    def _set_eip_here(self):
        addr = self._selected_code_addr()
        if addr is None or not self._need_halted():
            return
        if self.session.set_eip(addr):
            self._eip = addr
            self._set_dbg_state(f"EIP set to 0x{addr:08X}", "#FFD54F")
            self.render()
            self._refresh_debug_views()
        else:
            self._set_dbg_state(
                f"could not set EIP: {self.session.last_error}", "#f44336")

    def _bp_dialog(self, bp=None, addr=None, kind="execute"):
        """PCSX2-style breakpoint dialog: type, address, size, condition."""
        win = tk.Toplevel(self)
        win.title("Edit breakpoint" if bp else "New breakpoint")
        win.configure(bg="#212121")
        win.transient(self)
        win.resizable(False, False)
        pad = dict(padx=8, pady=4)

        kind_var = tk.StringVar(value=bp.kind if bp else kind)
        addr_var = tk.StringVar(
            value=f"0x{(bp.addr if bp else (addr if addr is not None else (self._selected_code_addr() or 0))):08X}")
        size_var = tk.StringVar(value=str(bp.size if bp else 4))
        cond_var = tk.StringVar(value=bp.condition if bp else "")
        label_var = tk.StringVar(value=bp.label if bp else "")
        on_var = tk.BooleanVar(value=bp.enabled if bp else True)
        # The address table shows PHYSICAL offsets and the stub only
        # understands GUEST VIRTUAL. Copying an address across silently armed
        # the breakpoint on an unrelated place, which never fires and gives no
        # hint why - so the space is now explicit and converted.
        space_var = tk.StringVar(value="Virtual")

        row = tk.Frame(win, bg="#212121"); row.pack(fill="x", **pad)
        tk.Label(row, text="Type:", fg="#E0E0E0", bg="#212121", width=9,
                 anchor="w", font=("Helvetica", 9)).pack(side="left")
        for text, val in (("Execute", "execute"), ("Write", "write"),
                          ("Read", "read"), ("Read+Write", "access")):
            tk.Radiobutton(row, text=text, variable=kind_var, value=val,
                           bg="#212121", fg="#E0E0E0", selectcolor="#424242",
                           activebackground="#212121",
                           activeforeground="#FFFFFF",
                           font=("Helvetica", 8)).pack(side="left")

        row = tk.Frame(win, bg="#212121"); row.pack(fill="x", **pad)
        tk.Label(row, text="Address:", fg="#E0E0E0", bg="#212121", width=9,
                 anchor="w", font=("Helvetica", 9)).pack(side="left")
        tk.Entry(row, textvariable=addr_var, width=14, bd=0, bg="#424242",
                 fg="#00FF88", insertbackground="white",
                 font=("Courier", 10)).pack(side="left")
        for text in ("Virtual", "Physical"):
            tk.Radiobutton(row, text=text, variable=space_var, value=text,
                           bg="#212121", fg="#E0E0E0", selectcolor="#424242",
                           activebackground="#212121",
                           activeforeground="#FFFFFF",
                           font=("Helvetica", 8)).pack(side="left")
        tk.Label(row, text="Size:", fg="#E0E0E0", bg="#212121",
                 font=("Helvetica", 9)).pack(side="left", padx=(10, 2))
        sm = tk.OptionMenu(row, size_var, "1", "2", "4", "8")
        sm.config(font=("Helvetica", 8), bg="#424242", fg="#E0E0E0", bd=0,
                  highlightthickness=0)
        sm.pack(side="left")

        row = tk.Frame(win, bg="#212121"); row.pack(fill="x", **pad)
        tk.Label(row, text="Condition:", fg="#E0E0E0", bg="#212121", width=9,
                 anchor="w", font=("Helvetica", 9)).pack(side="left")
        tk.Entry(row, textvariable=cond_var, width=46, bd=0, bg="#424242",
                 fg="#FFFFFF", insertbackground="white",
                 font=("Courier", 9)).pack(side="left", fill="x", expand=True)

        tk.Label(win, text="Registers by name, brackets for memory:\n"
                           "    eax == 0x10 && [esp+4] != 0\n"
                           "    u8[0x005FE4B0 + 0x88] < 25\n"
                           "Conditions are checked here, not in the emulator, "
                           "so a condition on a hot instruction slows the game "
                           "down while it is armed.",
                 fg="#78909C", bg="#212121", justify="left",
                 font=("Courier", 8)).pack(anchor="w", padx=16)

        row = tk.Frame(win, bg="#212121"); row.pack(fill="x", **pad)
        tk.Label(row, text="Note:", fg="#E0E0E0", bg="#212121", width=9,
                 anchor="w", font=("Helvetica", 9)).pack(side="left")
        tk.Entry(row, textvariable=label_var, width=46, bd=0, bg="#424242",
                 fg="#FFFFFF", insertbackground="white",
                 font=("Helvetica", 9)).pack(side="left", fill="x", expand=True)
        tk.Checkbutton(win, text="Enabled", variable=on_var, bg="#212121",
                       fg="#E0E0E0", selectcolor="#424242",
                       activebackground="#212121",
                       font=("Helvetica", 8)).pack(anchor="w", padx=16)

        err = tk.Label(win, text="", fg="#f44336", bg="#212121",
                       font=("Helvetica", 8))
        err.pack(anchor="w", padx=16)

        def ok():
            try:
                a = int(addr_var.get().strip().replace("0x", ""), 16)
            except ValueError:
                err.config(text="Address must be hex")
                return
            if space_var.get() == "Physical":
                pm = self.engine.ensure_pagemap()
                va = pm.to_virt(a) if pm else None
                if va is None:
                    err.config(
                        text=f"0x{a:08X} is not mapped, so it has no virtual "
                             f"address to break on")
                    return
                a = va
            elif not self._plausible_virtual(a):
                # Not fatal - the guest may simply not have that page mapped
                # yet - but it is nearly always a physical offset pasted in by
                # mistake, and a silent no-op breakpoint is the worst outcome.
                pm = self.engine.ensure_pagemap()
                alt = pm.to_virt(a) if pm else None
                err.config(
                    text=(f"0x{a:08X} is not mapped as a virtual address"
                          + (f" - did you mean 0x{alt:08X}? Pick Physical."
                             if alt is not None else
                             " - check the address before continuing.")),
                    fg="#FF9800")
                if not getattr(win, "_warned", False):
                    win._warned = True
                    return          # a second OK accepts it anyway
            cond = cond_var.get().strip()
            if cond:
                try:
                    compile_condition(cond)
                except ValueError as exc:
                    err.config(text=str(exc))
                    return
            if bp is None:
                self._add_bp(Breakpoint(a, kind_var.get(),
                                        int(size_var.get()), cond,
                                        on_var.get(), label_var.get()))
            else:
                # Re-arm from scratch: the address or type may have changed, and
                # the stub keys a breakpoint by both.
                if self.session is not None:
                    self.session.disarm(bp)
                bp.addr, bp.kind = a, kind_var.get()
                bp.size = 1 if bp.kind == "execute" else int(size_var.get())
                bp.condition, bp.label = cond, label_var.get()
                bp.enabled, bp.error = on_var.get(), ""
                if self.session is not None and bp.enabled:
                    self.session.arm(bp)
                self._refresh_bp_tree()
                self.render()
            win.destroy()

        row = tk.Frame(win, bg="#212121"); row.pack(fill="x", **pad)
        tk.Button(row, text="OK", command=ok, bd=0, bg="#4CAF50", fg="white",
                  padx=16, font=("Helvetica", 9, "bold")).pack(side="right",
                                                               padx=4)
        tk.Button(row, text="Cancel", command=win.destroy, bd=0, bg="#616161",
                  fg="white", padx=12,
                  font=("Helvetica", 9, "bold")).pack(side="right")
        win.bind("<Return>", lambda ev: ok())
        win.bind("<Escape>", lambda ev: win.destroy())

    # ---- registers editing ----------------------------------------------
    def _edit_register(self, event=None):
        t = self.dbg_trees.get("regs")
        sel = t.selection() if t else ()
        if not sel or not self._need_halted():
            return
        name = str(t.item(sel[0], "values")[0])
        if name not in GDB_X86_REGS:
            return
        cur = self.session.regs.get(name, 0)
        ans = simpledialog.askstring("Set register", f"New value for {name}:",
                                     initialvalue=f"0x{cur:08X}", parent=self)
        if not ans:
            return
        try:
            val = int(ans.strip(), 16) if ans.strip().lower().startswith("0x") \
                else int(ans.strip(), 0)
        except ValueError:
            self._set_dbg_state("value must be a number", "#f44336")
            return
        if self.session.set_register(name, val):
            self._eip = self.session.regs.get("eip")
            self.render()
            self._refresh_debug_views()
        else:
            self._set_dbg_state(f"could not set {name}: "
                                f"{self.session.last_error}", "#f44336")

    def _goto_frame(self, event=None):
        t = self.dbg_trees.get("frames")
        sel = t.selection() if t else ()
        if not sel:
            return
        try:
            self.goto(int(str(t.item(sel[0], "values")[1]), 16))
        except ValueError:
            pass

    # ---- globals ---------------------------------------------------------
    def _globals_from_function(self):
        """
        Collect absolute data addresses referenced by the code on screen.

        A global access compiles to an absolute displacement - mov eax,
        [0x005FE4B0] - so any operand that is a bare address inside .data or
        .rdata is a global this code touches. That is a real cross-reference,
        not a guess, and it is the fastest way to find the statics a function
        works on when there are no symbols.
        """
        try:
            import capstone
        except ImportError:
            self._set_dbg_state("capstone is required for this", "#f44336")
            return
        if self.top_va is None:
            return
        start = self.top_va
        label = self._nearest_name(start) or f"sub_{start:08X}"
        data = self._read(start, 0x600)
        if not data:
            self._set_dbg_state("nothing mapped at this address", "#FF9800")
            return
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        found = []
        for ins in md.disasm(data, start):
            if ins.mnemonic in ("ret", "retn") and ins.address > start:
                break
            for tok in re.findall(r"0x[0-9a-fA-F]+", ins.op_str):
                va = int(tok, 16)
                sec = self._section_of(va)
                if sec in ("data", ".data", ".rdata", "rdata") and \
                        "[" in ins.op_str:
                    found.append((va, f"{label} @ 0x{ins.address:08X}"))
        seen = {a for a, _ in self.globals_watch}
        added = 0
        for va, src in found:
            if va not in seen:
                self.globals_watch.append((va, src))
                seen.add(va)
                added += 1
        self._refresh_globals_tree()
        self._set_dbg_state(f"{added} global reference(s) added from {label}",
                            "#AED581" if added else "#78909C")

    def _globals_add(self):
        ans = simpledialog.askstring("Add global",
                                     "Guest virtual address (hex):",
                                     parent=self)
        if not ans:
            return
        try:
            va = int(ans.strip().replace("0x", ""), 16)
        except ValueError:
            self._set_dbg_state("address must be hex", "#f44336")
            return
        self.globals_watch.append((va, "added by hand"))
        self._refresh_globals_tree()

    def _globals_remove(self):
        t = self.dbg_trees.get("globals")
        sel = t.selection() if t else ()
        for iid in sel:
            try:
                va = int(str(t.item(iid, "values")[0]), 16)
            except ValueError:
                continue
            self.globals_watch = [(a, s) for a, s in self.globals_watch
                                  if a != va]
        self._refresh_globals_tree()

    def _globals_clear(self):
        self.globals_watch = []
        self._refresh_globals_tree()

    def _globals_to_table(self):
        """Hand the selected globals to the main window's address table."""
        t = self.dbg_trees.get("globals")
        sel = t.selection() if t else ()
        pm = self.engine.ensure_pagemap()
        sent = 0
        for iid in sel:
            try:
                va = int(str(t.item(iid, "values")[0]), 16)
            except ValueError:
                continue
            pa = pm.to_phys(va) if pm else None
            if pa is None:
                continue
            # The address table is a list of lists, not dicts:
            # [phys, desc, type, freeze, value, is_pointer, base, offsets,
            #  display_phys, group, id, is_virtual]. Plain entries are
            # physical, so the virtual address is translated on the way in.
            eng = self.engine
            eng.address_table.append(
                [pa, f"Global 0x{va:08X}", "int32", False, "0", False, 0, [],
                 pa, "Debugger", eng._next_entry_id, False])
            eng._next_entry_id += 1
            sent += 1
        if sent:
            self.master._rebuild_table = True
            self.master.update_table_view()
        self._set_dbg_state(
            f"{sent} address(es) sent to the table"
            if sent else "nothing sent - those addresses are not mapped",
            "#AED581" if sent else "#FF9800")

    def _globals_open_viewer(self, event=None):
        t = self.dbg_trees.get("globals")
        sel = t.selection() if t else ()
        if not sel:
            return
        try:
            va = int(str(t.item(sel[0], "values")[0]), 16)
        except ValueError:
            return
        self.master.open_mem_viewer(va, virtual=True)

    def _refresh_globals_tree(self):
        t = self._clear_tree("globals")
        if t is None:
            return
        for va, src in self.globals_watch:
            data = self._read(va, 4)
            val = int.from_bytes(data, "little") if len(data) == 4 else None
            t.insert("", "end",
                     values=(f"0x{va:08X}", self._section_of(va) or "?",
                             "" if val is None else f"0x{val:08X}",
                             self._signed(val), self._as_float(val), src),
                     tags=() if val is not None else ("dim",))


    # ======================================================================
    # LIVE UPDATE
    # ======================================================================
    # PCSX2's debugger keeps refreshing while the game runs, and that is what
    # is wanted here. Two halves, with very different costs:
    #
    #   Memory and code       free. Reads go through /proc/<pid>/mem and the
    #                         page map, which do not care whether the guest is
    #                         running. The disassembly, the raw stack and the
    #                         Globals tab can all refresh at any rate.
    #
    #   Registers             not free. The GDB remote protocol has no way to
    #                         read registers from a running target - the 'g'
    #                         packet only answers when the guest is halted. So
    #                         "live registers" is SAMPLING: interrupt, read,
    #                         continue, once per tick. Each sample stops the
    #                         guest for a fraction of a millisecond, which is
    #                         invisible at 100 ms but is a real cost at 1 ms,
    #                         and it is a separate tick box for that reason.
    #                         Anything labelled sampled is a snapshot from the
    #                         moment of the halt, not a continuous readout.

    LIVE_MIN, LIVE_MAX = 1, 1000

    def _build_live_controls(self, bar):
        tk.Checkbutton(bar, text="Live", variable=self.live_on,
                       command=self._restart_live, bg="#1A1A1A", fg="#E0E0E0",
                       selectcolor="#424242", activebackground="#1A1A1A",
                       activeforeground="#FFFFFF",
                       font=("Helvetica", 8, "bold")).pack(side="left",
                                                           padx=(8, 0))
        tk.Label(bar, text="every", fg="#B0BEC5", bg="#1A1A1A",
                 font=("Helvetica", 8)).pack(side="left", padx=(4, 2))
        sp = tk.Spinbox(bar, from_=self.LIVE_MIN, to=self.LIVE_MAX,
                        increment=10, width=5,
                        textvariable=self.live_interval, bd=0, bg="#424242",
                        fg="#FFFFFF", insertbackground="white",
                        buttonbackground="#616161", highlightthickness=0,
                        font=("Courier", 9), command=self._restart_live)
        sp.pack(side="left")
        sp.bind("<Return>", lambda ev: self._restart_live())
        sp.bind("<FocusOut>", lambda ev: self._restart_live())
        bind_wheel_number(sp, self.live_interval, self.LIVE_MIN, self.LIVE_MAX,
                          step=10)
        tk.Label(bar, text="ms", fg="#B0BEC5", bg="#1A1A1A",
                 font=("Helvetica", 8)).pack(side="left", padx=(2, 0))
        tk.Checkbutton(bar, text="Sample registers", variable=self.live_regs,
                       command=self._restart_live, bg="#1A1A1A", fg="#E0E0E0",
                       selectcolor="#424242", activebackground="#1A1A1A",
                       activeforeground="#FFFFFF",
                       font=("Helvetica", 8)).pack(side="left", padx=(6, 0))
        self.live_rate = tk.Label(bar, text="", fg="#78909C", bg="#1A1A1A",
                                  font=("Helvetica", 8))
        self.live_rate.pack(side="left", padx=4)

    def _live_ms(self):
        try:
            v = int(self.live_interval.get())
        except (ValueError, tk.TclError):
            v = 100
        v = max(self.LIVE_MIN, min(self.LIVE_MAX, v))
        if str(v) != str(self.live_interval.get()):
            self.live_interval.set(str(v))
        return v

    def _restart_live(self):
        """Re-arm the timer after the interval or the tick boxes changed."""
        if self._live_id is not None:
            try:
                self.after_cancel(self._live_id)
            except (ValueError, tk.TclError):
                pass
            self._live_id = None
        self._sample_times.clear()
        if not self.live_on.get():
            self.live_rate.config(text="paused")
            self._save_live_settings()
            return
        self.live_rate.config(text="")
        self._save_live_settings()
        self._live_id = self.after(self._live_ms(), self._live_tick)

    def _save_live_settings(self):
        """Persist the interval through the main window's config file."""
        cfg = getattr(self.master, "_config", None)
        if cfg is None:
            return
        try:
            if "debugger" not in cfg:
                cfg["debugger"] = {}
            cfg["debugger"]["live_interval_ms"] = str(self._live_ms())
            cfg["debugger"]["live_default"] = str(bool(self.live_on.get()))
            cfg["debugger"]["sample_registers"] = str(bool(self.live_regs.get()))
        except Exception:
            pass

    def _load_live_settings(self):
        cfg = getattr(self.master, "_config", None)
        if cfg is None or "debugger" not in cfg:
            return
        try:
            self.live_interval.set(str(max(self.LIVE_MIN, min(
                self.LIVE_MAX, cfg.getint("debugger", "live_interval_ms",
                                          fallback=100)))))
            self.live_on.set(cfg.getboolean("debugger", "live_default",
                                            fallback=True))
            self.live_regs.set(cfg.getboolean("debugger", "sample_registers",
                                              fallback=True))
        except Exception:
            pass

    def _live_tick(self):
        self._live_id = None
        if not self.winfo_exists():
            return
        if self._live_busy:                    # a slow tick is still running
            self._live_id = self.after(self._live_ms(), self._live_tick)
            return
        self._live_busy = True
        t0 = time.time()
        try:
            self._live_refresh_code()
            if self.live_regs.get():
                self._sample_registers()
        except (GdbStubError, OSError) as exc:
            self._set_dbg_state(f"stub error while sampling: {exc}", "#f44336")
            self.live_regs.set(False)
        except Exception as exc:               # noqa: BLE001
            self._set_dbg_state(f"live update error: {exc}", "#f44336")
            self.live_on.set(False)
        finally:
            self._live_busy = False
        cost = time.time() - t0
        self._sample_times.append(cost)
        if len(self._sample_times) > 20:
            self._sample_times.pop(0)
        if self.live_on.get():
            # If a tick costs more than the interval, back off to what is
            # actually achievable instead of queueing work faster than it
            # completes - the symptom of that is a UI that stops responding
            # rather than one that updates quickly.
            want = self._live_ms()
            avg = sum(self._sample_times) / len(self._sample_times)
            delay = max(want, int(avg * 1000 * 1.5))
            if delay > want:
                self.live_rate.config(text=f"{1000 / delay:.0f}/s (capped, "
                                           f"{avg * 1000:.1f} ms per update)")
            else:
                self.live_rate.config(text=f"{1000 / want:.0f}/s")
            self._live_id = self.after(delay, self._live_tick)

    def _live_refresh_code(self):
        """
        Re-render the code view only when something visible changed.

        Re-rendering unconditionally at a 10 ms interval fights with the user:
        the tree is rebuilt under the cursor, and scrolling and selection
        stutter. Code bytes almost never change, so the window is hashed and
        the render skipped when it matches - which also makes a live patch show
        up immediately, because that is a change.
        """
        if self.top_va is None:
            return
        n = self.visible_rows()
        data = self._read(self.top_va, n * 8 + 32)
        key = (self.top_va, hash(data), self._eip if self._eip in
               [a for a, _ in self._rows] else None,
               len(self.breakpoints), len(self.patches))
        if key == self._code_key:
            return
        self._code_key = key
        self.render()
        if self.fields is None and self.globals_watch:
            self._refresh_globals_tree()
        elif self.globals_watch:
            self._refresh_globals_tree()

    def _sample_registers(self):
        """
        Halt, read the registers, resume. See the note at the top.

        Skipped entirely when the guest is already halted at a breakpoint,
        because then the panels hold the real state and interrupting a halted
        guest would only confuse the stop bookkeeping.
        """
        sess = self.session
        if sess is None or not sess.connected or sess.stopped:
            return
        client = sess.client
        pkt = client.stop()
        if not pkt:
            # The interrupt byte halts the guest whether or not its reply
            # reaches us, so having sent one we owe a continue - the same rule
            # as DebugSession._pause_for_edit. Returning here used to leave the
            # emulator stopped with nothing tracking that it was, which is one
            # of the ways it froze while merely being watched.
            sess.stopped = False
            sess._pending = "run"
            try:
                client.cont()
            except (GdbStubError, OSError):
                pass
            return
        # The interrupt and a real breakpoint hit can arrive together, and then
        # this reply is the breakpoint's, not ours. Resuming out from under it
        # would silently run past the thing the user set the breakpoint for -
        # the symptom being a breakpoint that "sometimes does not work", only
        # while live sampling is on.
        info = parse_stop_reply(pkt)
        if info.get("watch") is not None or any(
                bp.enabled and bp.matches_stop(info, self._peek_eip(client))
                for bp in self.breakpoints):
            event = sess._on_stop(pkt)
            if event:
                self._handle_debug_event(*event)
            return
        try:
            sess.regs = client.registers()
            self._eip = sess.regs.get("eip")
            self.sampled = True
            self._refresh_sampled_views()
        finally:
            # Resume no matter what went wrong reading. Leaving the guest halted
            # because a panel refresh raised would look exactly like the
            # emulator hanging.
            try:
                client.cont()
            except (GdbStubError, OSError):
                pass
            sess.stopped = False
            sess._pending = "run"
        self._set_dbg_state(f"running - sampled at 0x{self._eip or 0:08X}",
                            "#4CAF50")

    def _peek_eip(self, client):
        """EIP for the stop reply just received, without disturbing anything."""
        try:
            return client.registers().get("eip", 0)
        except GdbStubError:
            return 0

    def _refresh_sampled_views(self):
        """The register-dependent panels, marked as a sample."""
        self._refresh_registers()
        self._refresh_stack()
        self._refresh_slots("locals")
        self._refresh_slots("params")
        for key in ("regs", "frames", "locals", "params"):
            t = self.dbg_trees.get(key)
            if t is not None and t.get_children():
                t.insert("", "end",
                         values=tuple(["(sampled while running)"]
                                      + [""] * 5)[:len(t["columns"])],
                         tags=("dim",))

    # ======================================================================
    # LIVE PATCHING
    # ======================================================================
    # Writing code bytes into a running guest works: xemu's JIT picks the new
    # bytes up on the next execution of that block (§5d). Writes go through the
    # page map to physical, per page, because a 15-byte instruction can straddle
    # a page boundary and the two halves are nowhere near each other in
    # physical RAM.

    def _write_code(self, va, data):
        """
        Write bytes at a guest virtual address. Returns an error or None.

        Prefers the stub when one is attached, and that is what makes a patch
        take effect NOW rather than eventually. See DebugSession.write_mem: a
        write straight into /proc changes the bytes but tells QEMU nothing, so
        the JIT keeps executing the block it already translated and the NOP
        appears to do nothing until that block is retranslated for some
        unrelated reason.
        """
        if self.session is not None and self.session.connected:
            if self.session.write_mem(va, data):
                return None
            # Fall through to the raw write; a stub error should not stop the
            # patch happening at all.
        pm = self.engine.ensure_pagemap()
        if pm is None:
            return "no page map - is a game running?"
        written = 0
        while written < len(data):
            pa = pm.to_phys(va + written)
            if pa is None:
                return f"0x{va + written:08X} is not mapped"
            step = min(len(data) - written, 0x1000 - ((va + written) & 0xFFF))
            try:
                self.engine.write_mem(self.engine.xbox_ram_base + pa,
                                      data[written:written + step])
            except Exception as exc:                  # noqa: BLE001
                return str(exc)
            written += step
        return None

    def _instruction_at(self, va):
        """(length, text) of the instruction at a virtual address."""
        rows = disassemble_at(self._read(va, 16), va, 1)
        addr, bhex, text = rows[0]
        return len(bhex.split()) or 1, text

    def _remember_original(self, va, length):
        """Keep the first version of these bytes so a patch can be undone."""
        if va in self.patches:
            return
        orig = self._read(va, length)
        if len(orig) != length and self.session is not None \
                and self.session.connected:
            # The page map could not answer; the stub can. Getting this wrong
            # makes a patch permanent, because undo restores what was recorded.
            orig = self.session.read_mem_paused(va, length)
        if len(orig) == length:
            self.patches[va] = orig

    def _nop_here(self, va=None):
        if va is None:
            va = self._selected_code_addr()
        if va is None:
            return
        n, text = self._instruction_at(va)
        self._remember_original(va, n)
        err = self._write_code(va, b"\x90" * n)
        if err:
            self.patches.pop(va, None)
            self._set_dbg_state(f"patch failed: {err}", "#f44336")
            return
        self._code_key = None
        self.render()
        live = self.session is not None and self.session.connected
        self._set_dbg_state(
            f"NOPed {n} byte(s) at 0x{va:08X}  ({text})"
            + ("  - live, in effect now" if live else
               "  - attach the debugger for it to take effect immediately"),
            "#FFD54F")

    def _patch_bytes_dialog(self, va=None):
        if va is None:
            va = self._selected_code_addr()
        if va is None:
            return
        n, text = self._instruction_at(va)
        cur = self._read(va, n)
        ans = simpledialog.askstring(
            "Patch bytes",
            f"0x{va:08X}   {text}\n"
            f"{n} byte(s). Shorter input is padded with 0x90 (nop); longer "
            f"input overwrites the following instruction too.",
            initialvalue=cur.hex(" "), parent=self)
        if ans is None:
            return
        try:
            data = bytes.fromhex(ans.replace(",", " ").replace("0x", ""))
        except ValueError:
            self._set_dbg_state("that is not a hex byte string", "#f44336")
            return
        if not data:
            return
        if len(data) < n:
            data += b"\x90" * (n - len(data))
        self._remember_original(va, len(data))
        err = self._write_code(va, data)
        if err:
            self._set_dbg_state(f"patch failed: {err}", "#f44336")
            return
        self._code_key = None
        self.render()
        self._set_dbg_state(f"wrote {len(data)} byte(s) at 0x{va:08X}",
                            "#FFD54F")

    def _undo_patch(self, va=None):
        if va is None:
            va = self._selected_code_addr()
        orig = self.patches.get(va)
        if orig is None:
            self._set_dbg_state("no patch recorded at that address", "#FF9800")
            return
        err = self._write_code(va, orig)
        if err:
            self._set_dbg_state(f"restore failed: {err}", "#f44336")
            return
        del self.patches[va]
        self._code_key = None
        self.render()
        self._set_dbg_state(f"restored {len(orig)} byte(s) at 0x{va:08X}",
                            "#AED581")

    def _undo_all_patches(self):
        failed = 0
        for va in list(self.patches):
            if self._write_code(va, self.patches[va]):
                failed += 1
            else:
                del self.patches[va]
        self._code_key = None
        self.render()
        self._set_dbg_state(
            "restored all patches" if not failed
            else f"{failed} patch(es) could not be restored - those pages are "
                 f"no longer mapped",
            "#AED581" if not failed else "#FF9800")

    # ---- worker pump -----------------------------------------------------
    def _pump(self):
        try:
            while True:
                kind, payload = self.inbox.get_nowait()
                if kind == "funcs":
                    self.funcs = payload
                    self.func_display = {}
                    self._refilter()
                    if self.top_va is None and payload:
                        self.goto(payload[0][0])
                elif kind == "index":
                    self.index = payload
                    self.funcs = payload.plain()
                    self.func_display = dict(payload.entries())
                    self._refilter()
                    msg = payload.summary()
                    if payload.debug_info:
                        msg += "  |  " + "; ".join(payload.debug_info)
                    self.status.config(text=msg, fg="#B0BEC5")
                    if self.top_va is None and self.funcs:
                        self.goto(self._entry_va or self.funcs[0][0])
                    self.render()
                elif kind == "scanprogress":
                    self.status.config(text=payload, fg="#FF9800")
                elif kind == "fields":
                    self.fields = payload
                    self.status.config(
                        text=payload.note,
                        fg="#CE93D8" if payload.flat else "#FF9800")
                    self.render()
                elif kind == "fieldprogress":
                    self.status.config(text=payload, fg="#CE93D8")
                elif kind == "threads":
                    self.guest_threads = payload
                    hit = sum(1 for r in payload if r["current"])
                    self.thread_note.config(
                        text=(f"{len(payload)} KTHREAD candidate(s); {hit} "
                              f"contain the current ESP"
                              + (" - the scan looks right"
                                 if hit == 1 else
                                 " - treat the list as unverified")),
                        fg="#AED581" if hit == 1 else "#FF9800")
                    self._refresh_threads()
                elif kind == "error":
                    self.status.config(text=payload, fg="#f44336")
        except Exception:
            pass
        if self.winfo_exists():
            self.after(150, self._pump)

