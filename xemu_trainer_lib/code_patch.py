"""
Code patches - assembly-level edits applied through xemu's gdbstub.

WHY THIS IS NOT PART OF THE ADDRESS TABLE
-----------------------------------------
The address table writes with /proc/<pid>/mem, which is right for data. Health,
ammo and timers are never translated, so a direct write is both correct and
fast enough to run every frame.

Code is different. xemu runs the Xbox's x86 under TCG unless KVM is available
(check with "info accel" in the Monitor - a "Translation buffer state" section
means TCG). TCG caches translated blocks keyed by physical address and only
invalidates them when the GUEST writes to a page holding translated code. A
write from outside the process bypasses that dirty tracking entirely, so the
new bytes sit in RAM while the stale translation keeps executing. The patch
looks applied and does nothing.

DebugSession.write_mem goes through the stub's M packet, which lands in QEMU's
cpu_memory_rw_debug() and invalidates the affected blocks. That is the "JIT
flush" - it already exists, it just needs to be what code patches use.

Consequences worth knowing:
  * Each apply halts the guest for a moment (the stub processes packets while
    stopped). Fine for one-shot patches, useless for per-frame freezing - that
    is what the address table is for.
  * Addresses here are GUEST VIRTUAL, because that is what the stub speaks.
    The address table stores physical offsets; use trainer._guest_virtual_for()
    to convert if you are copying an address across.
  * The stub must be running: type "gdbserver" in xemu's Monitor.
"""

import json
import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog

from .gdb_broker import gdb_broker
from .gdb_client import GdbStubError
from .ui_widgets import popup_menu


class CodePatch:
    """One contiguous byte patch at a guest virtual address."""

    def __init__(self, addr, data, desc="", enabled=False, original=None):
        self.addr = int(addr)
        self.data = bytes(data)
        self.desc = desc
        self.enabled = bool(enabled)
        # Captured from the guest the first time the patch is applied, never
        # from the saved file - a stale "original" written back over a
        # different build would corrupt code rather than restore it.
        self.original = bytes(original) if original else None

    def to_dict(self):
        return {"addr": self.addr, "data": self.data.hex(),
                "desc": self.desc, "enabled": self.enabled}

    @classmethod
    def from_dict(cls, d):
        return cls(int(d["addr"]), bytes.fromhex(d["data"]),
                   d.get("desc", ""), d.get("enabled", False))


def parse_hex_bytes(text):
    """
    Accept the shapes people actually paste: '90 90 90', '909090', '0x90,0x90'.
    """
    cleaned = (text.replace("0x", " ").replace("0X", " ")
                   .replace(",", " ").replace("\n", " ").strip())
    if " " in cleaned:
        parts = [p for p in cleaned.split(" ") if p]
        return bytes(int(p, 16) for p in parts)
    if len(cleaned) % 2:
        raise ValueError("odd number of hex digits")
    return bytes.fromhex(cleaned)


class CodePatchWindow(tk.Toplevel):
    """Manage, apply and revert code patches over the shared gdb session."""

    def __init__(self, master, engine):
        super().__init__(master)
        self.title("Code Patches")
        self.configure(bg="#212121")
        self.geometry("640x420")
        self.engine = engine
        self.patches = []
        self._build()
        self.protocol("WM_DELETE_WINDOW", self._close)

    # ---- session ---------------------------------------------------------
    def _session(self):
        """
        Join the shared gdb session, or explain why we cannot.

        The broker is shared with the disassembler and watchpoint windows, so
        acquiring here does not fight them for the socket.
        """
        try:
            return gdb_broker(self).acquire(self, self.engine,
                                            label="Code patches")
        except (GdbStubError, OSError) as exc:
            messagebox.showerror(
                "gdbstub",
                "Could not reach xemu's gdbstub.\n\n"
                "Open xemu's Monitor (backtick, or Debug -> Monitor) and "
                f"type:\n\n    gdbserver\n\nDetail: {exc}", parent=self)
            return None

    # ---- apply / revert --------------------------------------------------
    def _apply(self, patch, sess):
        if patch.original is None:
            try:
                patch.original = sess.read_mem(patch.addr, len(patch.data))
            except Exception as exc:                        # noqa: BLE001
                return f"could not read original bytes ({exc})"
            if patch.original is None or len(patch.original) != len(patch.data):
                patch.original = None
                return "could not read original bytes"
        if not sess.write_mem(patch.addr, patch.data):
            return sess.last_error or "write rejected by the stub"
        # Read back. A write can be accepted and still not stick if the
        # address is unmapped or in ROM, and silently-not-applied is the
        # single most confusing failure mode for this kind of patch.
        try:
            check = sess.read_mem(patch.addr, len(patch.data))
            if check is not None and bytes(check) != patch.data:
                return "wrote, but memory did not change (ROM or unmapped?)"
        except Exception:                                   # noqa: BLE001
            pass
        patch.enabled = True
        return None

    def _revert(self, patch, sess):
        if patch.original is None:
            return "no original bytes captured - never applied this session"
        if not sess.write_mem(patch.addr, patch.original):
            return sess.last_error or "write rejected by the stub"
        patch.enabled = False
        return None

    def _run_over(self, patches, fn, verb):
        if not patches:
            return
        sess = self._session()
        if sess is None:
            return
        failed = []
        try:
            for p in patches:
                err = fn(p, sess)
                if err:
                    failed.append(f"0x{p.addr:08X} {p.desc}: {err}")
        finally:
            # Release resumes the guest if we were the last owner. Without it
            # a failed patch could leave xemu halted with no visible cause.
            gdb_broker(self).release(self)
        self._refresh()
        if failed:
            messagebox.showwarning(
                f"{verb} patches",
                f"{len(failed)} of {len(patches)} failed:\n\n"
                + "\n".join(failed[:10]), parent=self)

    # ---- actions ---------------------------------------------------------
    def _selected(self):
        return [self.patches[i] for i in self.listbox.curselection()]

    def _apply_selected(self):
        self._run_over(self._selected(), self._apply, "Apply")

    def _revert_selected(self):
        self._run_over(self._selected(), self._revert, "Revert")

    def _apply_all(self):
        self._run_over([p for p in self.patches if p.enabled],
                       self._apply, "Re-apply")

    def _add(self, patch=None):
        addr = simpledialog.askstring(
            "Patch address", "Guest VIRTUAL address (hex):",
            initialvalue=f"{patch.addr:08X}" if patch else "", parent=self)
        if not addr:
            return
        raw = simpledialog.askstring(
            "Patch bytes", "New bytes (hex, e.g. 90 90 90):",
            initialvalue=patch.data.hex(" ") if patch else "", parent=self)
        if raw is None:
            return
        desc = simpledialog.askstring(
            "Description", "What does this patch do?",
            initialvalue=patch.desc if patch else "", parent=self) or ""
        try:
            va = int(addr.strip().replace("0x", ""), 16)
            data = parse_hex_bytes(raw)
        except ValueError as exc:
            messagebox.showerror("Bad input", str(exc), parent=self)
            return
        if not data:
            return
        if patch is not None:
            self.patches.remove(patch)
        self.patches.append(CodePatch(va, data, desc))
        self._refresh()

    def _edit(self):
        sel = self._selected()
        if len(sel) == 1:
            self._add(sel[0])

    def _remove(self):
        sel = self._selected()
        still_on = [p for p in sel if p.enabled]
        if still_on and not messagebox.askyesno(
                "Remove patches",
                f"{len(still_on)} of these are still applied in the guest.\n"
                "Removing them here will NOT revert them. Continue?",
                parent=self):
            return
        for p in sel:
            self.patches.remove(p)
        self._refresh()

    # ---- persistence -----------------------------------------------------
    def _save(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".json", parent=self,
            filetypes=[("Patch list", "*.json"), ("All files", "*.*")])
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump([p.to_dict() for p in self.patches], f, indent=2)

    def _load(self):
        path = filedialog.askopenfilename(
            parent=self,
            filetypes=[("Patch list", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as f:
                loaded = [CodePatch.from_dict(d) for d in json.load(f)]
        except Exception as exc:                            # noqa: BLE001
            messagebox.showerror("Load", str(exc), parent=self)
            return
        # Enabled means "was applied when saved", not "is applied now" - the
        # guest has been restarted since. Clear it so Re-apply is deliberate.
        for p in loaded:
            p.enabled = False
        self.patches = loaded
        self._refresh()

    # ---- ui --------------------------------------------------------------
    def _refresh(self):
        keep = set(self.listbox.curselection())
        self.listbox.delete(0, tk.END)
        for p in self.patches:
            mark = "ON " if p.enabled else "   "
            self.listbox.insert(
                tk.END,
                f"{mark} 0x{p.addr:08X}  {p.data.hex(' '):<24}  {p.desc}")
            self.listbox.itemconfig(
                tk.END, fg="#A5D6A7" if p.enabled else "#E0E0E0")
        for i in keep:
            if i < len(self.patches):
                self.listbox.selection_set(i)

    def _build(self):
        tk.Label(self, bg="#212121", fg="#B0BEC5", justify="left",
                 font=("Helvetica", 9),
                 text="Applied through xemu's gdbstub so the JIT sees them. "
                      "Start it with 'gdbserver' in xemu's Monitor.\n"
                      "Addresses are guest VIRTUAL, not table offsets."
                 ).pack(anchor="w", padx=8, pady=(8, 4))

        self.listbox = tk.Listbox(self, bg="#151515", fg="#E0E0E0",
                                  selectmode="extended", activestyle="none",
                                  font=("Courier", 10),   # "monospace" is an X11 alias Windows Tk
                                  # does not resolve; it would silently
                                  # fall back to a proportional font and
                                  # misalign every hex column.
                                  selectbackground="#0D3A5C")
        self.listbox.pack(fill="both", expand=True, padx=8)
        self.listbox.bind("<Double-Button-1>", lambda e: self._edit())
        self.listbox.bind("<Button-3>", self._context)

        bar = tk.Frame(self, bg="#212121")
        bar.pack(fill="x", padx=8, pady=8)
        for text, cmd, colour in (
                ("Add", self._add, "#4CAF50"),
                ("Edit", self._edit, "#607D8B"),
                ("Remove", self._remove, "#f44336"),
                ("Apply", self._apply_selected, "#FF9800"),
                ("Revert", self._revert_selected, "#795548"),
                ("Re-apply all", self._apply_all, "#3F51B5"),
                ("Load", self._load, "#455A64"),
                ("Save", self._save, "#455A64")):
            tk.Button(bar, text=text, command=cmd, bg=colour, fg="white",
                      relief="flat", padx=8, pady=3,
                      font=("Helvetica", 9, "bold")).pack(side="left", padx=2)

    def _context(self, event):
        menu = tk.Menu(self, tearoff=0, bg="#424242", fg="#FFFFFF",
                       activebackground="#FF9800", activeforeground="#000000")
        menu.add_command(label="Apply", command=self._apply_selected)
        menu.add_command(label="Revert", command=self._revert_selected)
        menu.add_separator()
        menu.add_command(label="Edit", command=self._edit)
        menu.add_command(label="Remove", command=self._remove)
        self._menu = menu
        popup_menu(menu, event.x_root, event.y_root)

    def _close(self):
        gdb_broker(self).release(self)
        self.destroy()


def open_code_patch_window(trainer_window):
    """Open (or raise) the code patch window."""
    existing = getattr(trainer_window, '_code_patch_win', None)
    if existing is not None and existing.winfo_exists():
        existing.lift()
        return existing
    win = CodePatchWindow(trainer_window, trainer_window.engine)
    trainer_window._code_patch_win = win
    return win
