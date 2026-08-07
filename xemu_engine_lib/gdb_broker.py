"""Shared GDB connection broker and the watchpoint window.

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
from .debug_session import Breakpoint, DebugSession  # noqa: F401
from .gdb_client import GdbClient, GdbStubError, disassemble_at  # noqa: F401
from .ui_widgets import GDB_DEFAULT_HOST, GDB_DEFAULT_PORT, bind_wheel, bind_wheel_cycle  # noqa: F401


class GdbBroker:
    """Shared owner of the single gdbstub connection."""

    POLL_MS = 60

    def __init__(self, root):
        self.root = root
        self.session = None
        self.owners = {}            # owner object -> label, for diagnostics
        self.subscribers = []
        self._poll_id = None
        self._last_error = ""
        self.host = GDB_DEFAULT_HOST
        self.port = GDB_DEFAULT_PORT

    # ---- ownership -------------------------------------------------------
    @property
    def connected(self):
        return self.session is not None and self.session.connected

    def acquire(self, owner, engine, host=None, port=None, read_fallback=None,
                label="", break_on_attach=False):
        """
        Join the shared session, connecting it if this is the first owner.

        Returns the DebugSession. Raises GdbStubError/OSError if the connection
        cannot be made, exactly as a direct connect would, so callers keep the
        error handling they already have.
        """
        if not self.connected:
            self.host = host or self.host
            self.port = port or self.port
            sess = DebugSession(engine, read_fallback=read_fallback,
                                host=self.host, port=self.port)
            sess.connect(break_on_attach=break_on_attach)
            self.session = sess
            self._start_poll()
        self.owners[owner] = label or type(owner).__name__
        return self.session

    def release(self, owner):
        """
        Leave the session; the last one out closes it and RESUMES THE GUEST.

        Resuming is the part that matters. A watchpoint hit halts the guest,
        and if the window that armed it goes away without continuing, xemu sits
        frozen. disconnect() disarms everything and continues before closing.
        """
        self.owners.pop(owner, None)
        self.subscribers = [s for s in self.subscribers if s[0] is not owner]
        if self.owners or self.session is None:
            return
        try:
            # Belt and braces: disconnect() resumes too, but only if it thinks
            # the guest is halted.
            self.session.force_resume()
        except Exception:                                   # noqa: BLE001
            pass
        try:
            self.session.disconnect()
        except Exception:                                   # noqa: BLE001
            pass
        self.session = None
        self._stop_poll()

    def reconnect(self, engine, read_fallback=None):
        """
        Re-open the connection, keeping owners, subscribers and breakpoints.

        xemu leaves the stub listening after a client goes away, so a dropped
        connection does not need `gdbserver none` / `gdbserver` in the Monitor -
        it needs a new socket. Breakpoints are re-armed from the windows that
        own them, so a reconnect restores the session rather than resetting it.
        """
        if not self.owners:
            return False
        old_bps = list(self.session.breakpoints) if self.session else []
        if self.session is not None:
            try:
                self.session.client.close()
            except Exception:                               # noqa: BLE001
                pass
        sess = DebugSession(engine, read_fallback=read_fallback,
                            host=self.host, port=self.port)
        try:
            sess.connect()
        except (GdbStubError, OSError) as exc:
            self._last_error = str(exc)
            self.session = None
            return False
        for bp in old_bps:
            bp.armed = False
            sess.breakpoints.append(bp)
            sess.arm(bp)
        self.session = sess
        self._start_poll()
        return True

    def subscribe(self, owner, callback):
        """callback(kind, payload) on the Tk thread for every stub event."""
        self.subscribers.append((owner, callback))

    def unsubscribe(self, owner, callback=None):
        self.subscribers = [
            s for s in self.subscribers
            if not (s[0] is owner and (callback is None or s[1] is callback))]

    def owner_summary(self):
        return ", ".join(sorted(self.owners.values())) or "nobody"

    # ---- the single poll -------------------------------------------------
    def _start_poll(self):
        if self._poll_id is None:
            self._poll_id = self.root.after(self.POLL_MS, self._pump)

    def _stop_poll(self):
        if self._poll_id is not None:
            try:
                self.root.after_cancel(self._poll_id)
            except Exception:                               # noqa: BLE001
                pass
            self._poll_id = None

    def pump_once(self):
        """
        Drain events and hand them to subscribers. Safe to call directly.

        A breakpoint marked auto_resume (a watchpoint someone is logging) is
        continued here once every subscriber has had its look at the halted
        state - they need the registers and the stack, which only exist while
        the guest is stopped.
        """
        if not self.connected:
            return []
        events = []
        try:
            for ev in self.session._drain_deferred():
                events.append(ev)
                self._dispatch(ev)
            for _ in range(16):
                ev = self.session.poll_one()
                if ev is None:
                    break
                events.append(ev)
                # Dispatched IMMEDIATELY, while the guest is still halted for
                # this particular stop - subscribers need its registers, stack
                # and code, and the next stop overwrites all three.
                self._dispatch(ev)
                if not self.connected:
                    break
        except (GdbStubError, OSError) as exc:
            events.append(("error", str(exc)))
            # ONLY tear down when the socket is genuinely gone.
            #
            # Any error used to drop the whole connection, and a transient one -
            # a register read that timed out because the guest had just halted,
            # say - therefore killed a working session at the exact moment a
            # breakpoint fired. Every window then showed "Attach", the emulator
            # was left paused with no Run button to press, and the only way back
            # was `gdbserver none` / `gdbserver` in xemu's Monitor and Ctrl+P by
            # hand. A timeout is not a dead socket.
            if self.session is not None and getattr(self.session.client, "dead",
                                                    False):
                try:
                    self.session.client.close()
                except Exception:                           # noqa: BLE001
                    pass
                self.session = None
                self.owners.clear()
                self._stop_poll()
            self._last_error = str(exc)
        return events

    def _dispatch(self, ev):
        kind, payload = ev
        for _owner, cb in list(self.subscribers):
            try:
                cb(kind, payload)
            except Exception:                               # noqa: BLE001
                pass
        if kind == "stopped" and self.connected and self.session.stopped:
            bp = payload.get("bp")
            resume = bp is not None and getattr(bp, "auto_resume", False)
            # A stop nobody claimed, while something that wants to keep running
            # is armed, must not leave the emulator halted. Being wrong here
            # costs a missed log line; the alternative costs a frozen game with
            # no way back except detaching.
            if not resume and payload.get("unclaimed") \
                    and self.session.any_auto_resume():
                resume = True
            if resume:
                try:
                    self.session.cont()
                except (GdbStubError, OSError):
                    pass

    # A watchpoint on a busy address fires far more often than a 60 ms timer
    # ticks, and one hit per tick means the guest advances a few instructions a
    # second - indistinguishable from a freeze. So each tick keeps draining
    # while hits keep arriving, bounded by wall time so the UI still responds.
    BURST_MS = 25

    def _pump(self):
        self._poll_id = None
        try:
            deadline = time.time() + self.BURST_MS / 1000.0
            while True:
                events = self.pump_once()
                if not events or not self.connected:
                    break
                if not self.session.stopped and time.time() < deadline:
                    continue          # it resumed; there may be more waiting
                break
        finally:
            if self.connected:
                self._poll_id = self.root.after(self.POLL_MS, self._pump)

def gdb_broker(widget):
    """The one broker for this application, created on first use."""
    root = widget.winfo_toplevel()
    while getattr(root, 'master', None) is not None:
        root = root.master.winfo_toplevel()
    existing = getattr(root, '_gdb_broker', None)
    if existing is None:
        existing = GdbBroker(root)
        root._gdb_broker = existing
    return existing

class GdbWatchWindow(tk.Toplevel):
    """
    "Find what accesses this address", via xemu's guest gdbstub.

    Start the stub from xemu's Monitor with:   gdbserver
    and stop it again with:                     gdbserver none

    Each hit is keyed by EIP and counted, so a write in a loop collapses to one
    row with a hit count rather than flooding the list.
    """

    def __init__(self, master, address, label="", kind="writes"):
        super().__init__(master)
        self.title(f"Find out what {kind} 0x{address:08X}")
        self.geometry("760x460")
        self.configure(bg="#212121")
        self.transient(master)
        self.address = address
        self.client = None          # kept for compatibility; unused now
        self.session = None
        self.bp = None
        self.worker = None
        self.running = False
        self.hits = {}
        # The worker thread must NOT touch Tk. Calling after() from another
        # thread raises "main thread is not in main loop" and is unsafe even
        # when it appears to work, so hits go through a queue that the GUI
        # thread drains on a timer.
        import queue
        self.inbox = queue.Queue()
        self._pump_id = None

        top = tk.Frame(self, bg="#212121"); top.pack(fill="x", padx=10, pady=8)
        tk.Label(top, text=f"Watching 0x{address:08X}  {label}",
                 font=("Helvetica", 10, "bold"), fg="#FF9800",
                 bg="#212121").pack(side="left")

        cfg = tk.Frame(self, bg="#212121"); cfg.pack(fill="x", padx=10)
        tk.Label(cfg, text="Host:", fg="#E0E0E0", bg="#212121",
                 font=("Helvetica", 8)).pack(side="left")
        self.host_var = tk.StringVar(value=GDB_DEFAULT_HOST)
        tk.Entry(cfg, textvariable=self.host_var, width=12, bd=0,
                 bg="#424242", fg="#FFFFFF").pack(side="left", padx=(2, 8))
        tk.Label(cfg, text="Port:", fg="#E0E0E0", bg="#212121",
                 font=("Helvetica", 8)).pack(side="left")
        self.port_var = tk.StringVar(value=str(GDB_DEFAULT_PORT))
        tk.Entry(cfg, textvariable=self.port_var, width=6, bd=0,
                 bg="#424242", fg="#FFFFFF").pack(side="left", padx=(2, 8))
        tk.Label(cfg, text="Watch:", fg="#E0E0E0", bg="#212121",
                 font=("Helvetica", 8)).pack(side="left")
        self.kind_var = tk.StringVar(
            value=kind if kind in ("writes", "reads", "reads + writes")
            else "writes")
        km = tk.OptionMenu(cfg, self.kind_var, "writes", "reads",
                           "reads + writes")
        km.config(font=("Helvetica", 8), bg="#424242", fg="#E0E0E0", bd=0,
                  highlightthickness=0)
        km.pack(side="left", padx=2)
        bind_wheel_cycle(km, ["writes", "reads", "reads + writes"],
                         self.kind_var.get, self.kind_var.set)
        tk.Label(cfg, text="Size:", fg="#E0E0E0", bg="#212121",
                 font=("Helvetica", 8)).pack(side="left", padx=(8, 0))
        self.pause_on_hit = tk.BooleanVar(value=False)
        self.size_var = tk.StringVar(value="4")
        sm = tk.OptionMenu(cfg, self.size_var, "1", "2", "4")
        sm.config(font=("Helvetica", 8), bg="#424242", fg="#E0E0E0", bd=0,
                  highlightthickness=0)
        sm.pack(side="left", padx=2)
        # Unchecked, the game keeps running and hits are logged as they happen.
        # Checked, the guest stays halted on the first hit so the debugger can
        # be used to look around at the moment of the access.
        tk.Checkbutton(cfg, text="Pause the game on each hit",
                       variable=self.pause_on_hit, bg="#212121", fg="#E0E0E0",
                       selectcolor="#424242", activebackground="#212121",
                       activeforeground="#FFFFFF",
                       font=("Helvetica", 8)).pack(side="left", padx=(10, 0))

        self.btn = tk.Button(cfg, text="Start", command=self.toggle,
                             font=("Helvetica", 9, "bold"), bg="#4CAF50",
                             fg="white", relief="flat", padx=14)
        self.btn.pack(side="right", padx=4)

        self.status = tk.Label(self, text="Start xemu's stub from the Monitor: "
                                          "gdbserver", fg="#B0BEC5",
                               bg="#212121", font=("Helvetica", 8))
        self.status.pack(anchor="w", padx=12, pady=(4, 0))

        body = tk.Frame(self, bg="#212121")
        body.pack(fill="both", expand=True, padx=10, pady=8)
        self.tree = ttk.Treeview(body, columns=("eip", "hits", "asm", "callers"),
                                 show="headings")
        for c, t, w in (("eip", "Instruction", 100), ("hits", "Hits", 50),
                        ("asm", "Disassembly", 360),
                        ("callers", "Called from", 220)):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w,
                             anchor="w" if c == "asm" else "center")
        sb = ttk.Scrollbar(body, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        bind_wheel(self.tree, lambda d: self.tree.yview_scroll(d * 3, "units"))

        tk.Label(self, text="Shared setters show the same instruction for every "
                            "caller - use 'Called from' to tell them apart.",
                 fg="#78909C",
                 bg="#212121", font=("Helvetica", 8)).pack(anchor="w",
                                                           padx=12, pady=(0, 6))
        self.protocol("WM_DELETE_WINDOW", self.close)
        self._pump()

    def _pump(self):
        """Drain worker messages on the GUI thread."""
        try:
            while True:
                kind, payload = self.inbox.get_nowait()
                if kind == "hit":
                    self._record(*payload)
                elif kind == "error":
                    self.status.config(text=payload, fg="#f44336")
                    self.stop()
        except Exception:
            pass
        if self.winfo_exists():
            self._pump_id = self.after(100, self._pump)

    # ---- control ---------------------------------------------------------
    def toggle(self):
        self.stop() if self.running else self.start()

    def kind(self):
        return {"writes": GdbClient.WRITE, "reads": GdbClient.READ,
                "reads + writes": GdbClient.ACCESS}[self.kind_var.get()]

    KIND_NAME = {"writes": "write", "reads": "read",
                 "reads + writes": "access"}

    def start(self):
        """
        Arm the watchpoint on the SHARED session.

        No socket and no worker thread of its own. If the debugger window is
        already attached this joins that connection instead of opening a second
        one the stub will not accept, and the host/port boxes are ignored
        because the connection already exists.
        """
        try:
            port = int(self.port_var.get())
        except ValueError:
            self.status.config(text="Port must be a number", fg="#f44336")
            return
        broker = gdb_broker(self)
        try:
            self.session = broker.acquire(
                self, self.master.engine, host=self.host_var.get(), port=port,
                label=f"Watch 0x{self.address:08X}")
        except Exception as e:
            self.status.config(
                text=f"Could not connect: {e}. In xemu's Monitor, run: "
                     f"gdbserver", fg="#f44336")
            self.session = None
            return
        try:
            self.bp = Breakpoint(self.address,
                                 self.KIND_NAME[self.kind_var.get()],
                                 int(self.size_var.get()),
                                 label="find what accesses")
            # The broker resumes the guest after each hit is recorded, so the
            # game keeps running instead of freezing on the first access.
            # Unchecked (the default) the game keeps running and hits are
            # logged as they happen; checked, the guest stays halted on the
            # first hit so you can look around in the debugger.
            self.bp.auto_resume = not self.pause_on_hit.get()
            self.session.add(self.bp)
            if not self.bp.armed:
                raise GdbStubError(self.bp.error or "the stub refused it")
        except Exception as e:
            self.status.config(text=f"Could not arm the watchpoint: {e}",
                               fg="#f44336")
            self._detach()
            return
        broker.subscribe(self, self._on_event)
        self.running = True
        self.btn.config(text="Stop", bg="#f44336")
        shared = len(broker.owners) > 1
        self.status.config(
            text="Watching - play the game and it will fill in."
                 + ("   (sharing the debugger's connection)" if shared else ""),
            fg="#4CAF50")

    def _on_event(self, kind, payload):
        """Called on the Tk thread by the broker, while the guest is halted."""
        if not self.running or kind != "stopped":
            return
        if payload.get("inferred") and payload.get("bp") is self.bp:
            self._say_inferred()
        bp = payload.get("bp")
        if bp is not self.bp:
            # An unattributed stop with no other watchpoint armed is ours: the
            # stub simply did not say which one fired.
            if not (bp is None and payload.get("unclaimed")
                    and self.session is not None
                    and self.session.sole_watchpoint() is self.bp):
                return
            self._say_inferred()
        sess = self.session
        try:
            regs = sess.regs or {}
            # From the payload, not from the session: by the time several stops
            # have been seen, session.regs describes the most recent one.
            eip = payload.get("eip") or regs.get("eip")
            code = sess.read_mem(eip - 16, 32) if eip else b""
            # Shared setters (CNetworkVar, memcpy, and friends) are where the
            # write physically happens, which tells you nothing about WHICH
            # weapon did it. The return addresses on the stack do.
            stack = sess.read_mem(regs.get("esp", 0), 128) if regs else b""
        except Exception:                                   # noqa: BLE001
            return
        if eip:
            self._record(eip, code, stack)

    def _say_inferred(self):
        self.status.config(
            text="Recording hits - the stub is not naming the watchpoint, so "
                 "these are attributed by inference.", fg="#FF9800")

    def _detach(self):
        """Drop the watchpoint and leave the shared session."""
        broker = gdb_broker(self)
        broker.unsubscribe(self)
        if self.session is not None and self.bp is not None:
            try:
                self.session.remove(self.bp)
            except Exception:                               # noqa: BLE001
                pass
        self.bp = None
        if self.session is not None:
            broker.release(self)
        self.session = None

    def stop(self):
        self.running = False
        self._detach()
        self.btn.config(text="Start", bg="#4CAF50")
        self.status.config(text="Stopped.", fg="#B0BEC5")

    def close(self):
        # Always pull the watchpoint back out: one left armed halts the guest
        # the next time it fires with nobody listening, and that looks exactly
        # like xemu hanging.
        self.running = False
        if self._pump_id is not None:
            try: self.after_cancel(self._pump_id)
            except Exception: pass
            self._pump_id = None
        self._detach()
        self.destroy()

    # The worker thread that used to live here is gone. It ran its own
    # stop/continue loop on a second connection to the stub, which is what made
    # watchpoints unreliable whenever the debugger was also attached.

    # The XBE image spans roughly this range; a stack dword inside it is a
    # plausible return address. Narrow enough to filter out data, wide enough
    # not to depend on the exact image size.
    IMAGE_LO, IMAGE_HI = 0x00011000, 0x00A00000

    def _callers_from_stack(self, stack):
        out = []
        for i in range(0, len(stack) - 3, 4):
            v = int.from_bytes(stack[i:i + 4], "little")
            if self.IMAGE_LO <= v < self.IMAGE_HI and v not in out:
                out.append(v)
            if len(out) >= 4:
                break
        return out

    def _record(self, eip, code, stack=b""):
        """
        Log one hit. The reported EIP is normally the instruction AFTER the
        access, so decode a window ending at it and show the last few.
        """
        callers = self._callers_from_stack(stack)
        if eip in self.hits:
            item, n, seen = self.hits[eip]
            for c in callers:
                if c not in seen:
                    seen.append(c)
            self.hits[eip] = (item, n + 1, seen)
            self.tree.set(item, "hits", n + 1)
            self.tree.set(item, "callers",
                          "  ".join(f"0x{c:08X}" for c in seen[:4]))
            return
        text = ""
        for start in range(16, 0, -1):
            lines = disassemble_at(code[16 - start:], eip - start, count=8)
            if any(a == eip for a, _, _ in lines):
                prev = [l for l in lines if l[0] < eip][-2:]
                text = "   |   ".join(f"0x{a:08X} {t}" for a, _, t in prev)
                break
        if not text:
            text = "(could not align the disassembly)"
        item = self.tree.insert(
            "", "end",
            values=(f"0x{eip:08X}", 1, text,
                    "  ".join(f"0x{c:08X}" for c in callers[:4])))
        self.hits[eip] = (item, 1, list(callers))

