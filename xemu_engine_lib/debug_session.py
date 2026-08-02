"""Breakpoints, conditions, and the stateful debug session.

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
from .gdb_client import GDB_X86_REGS, GdbClient, GdbStubError, disassemble_at  # noqa: F401
from .ui_widgets import GDB_DEFAULT_HOST, GDB_DEFAULT_PORT  # noqa: F401


def parse_stop_reply(pkt):
    """
    Decode a T/S stop reply into a dict.

    QEMU sends e.g.  T05thread:p1.1;watch:1420fa30;
    The signal is always 05 (SIGTRAP) for our purposes; what tells breakpoints
    apart from watchpoints is the presence of a watch/rwatch/awatch key.
    """
    info = {"signal": None, "thread": None, "watch": None, "watch_kind": None,
            "raw": pkt}
    if not pkt:
        return info
    if pkt[0] in "TS":
        try:
            info["signal"] = int(pkt[1:3], 16)
        except ValueError:
            pass
        for field in pkt[3:].split(";"):
            if ":" not in field:
                continue
            key, _, val = field.partition(":")
            key = key.lower()
            if key == "thread":
                info["thread"] = val
            elif key in ("watch", "rwatch", "awatch"):
                try:
                    info["watch"] = int(val, 16)
                except ValueError:
                    pass
                info["watch_kind"] = {"watch": "write", "rwatch": "read",
                                      "awatch": "access"}[key]
    elif pkt[0] in "WX":
        info["signal"] = -1                     # guest exited
    return info

_COND_NODES = None

def _cond_nodes():
    global _COND_NODES
    if _COND_NODES is None:
        import ast
        _COND_NODES = (
            ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.UnaryOp, ast.Not,
            ast.USub, ast.UAdd, ast.Invert, ast.BinOp, ast.Add, ast.Sub,
            ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.LShift, ast.RShift,
            ast.BitOr, ast.BitXor, ast.BitAnd, ast.Compare, ast.Eq, ast.NotEq,
            ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.Call, ast.Name, ast.Load,
            ast.Constant, ast.Tuple, ast.In, ast.NotIn)
    return _COND_NODES

def compile_condition(expr):
    """
    Compile a PCSX2-style breakpoint condition.

    Accepted:
        eax == 0x10 && ecx != 0
        [esp+4] > 100                 bare brackets are a 32-bit read
        u8[0x005FE4B0 + 0x88] == 5    u8/u16/u32 pick the width
        (eip & 0xFFFF0000) == 0x330000
        !ebx

    Returns a code object to be evaluated against the register/memory
    namespace, or raises ValueError with something a user can act on.
    """
    import ast
    src = expr.strip()
    if not src:
        raise ValueError("empty condition")
    src = src.replace("&&", " and ").replace("||", " or ")
    # A bare ! is "not", but != must survive. Python's own operators (&, |, ^,
    # <<, >>) are already correct so they are left alone.
    src = re.sub(r"!(?!=)", " not ", src)
    # Memory dereference. The sized prefixes go first so that u8[...] does not
    # get picked up by the bare-bracket rule below.
    src = re.sub(r"\bu(8|16|32)\s*\[", r"mem\1(", src)
    src = src.replace("[", "mem32(").replace("]", ")")
    # A leading "!" becomes " not", and ast.parse in eval mode reads a leading
    # space as an indent, so the rewritten text has to be stripped again.
    src = src.strip()
    try:
        tree = ast.parse(src, mode="eval")
    except SyntaxError as exc:
        raise ValueError(f"cannot parse condition: {exc.msg}") from None
    allowed = _cond_nodes()
    for node in ast.walk(tree):
        if not isinstance(node, allowed):
            raise ValueError(
                f"{type(node).__name__} is not allowed in a condition")
        if isinstance(node, ast.Call) and (
                not isinstance(node.func, ast.Name)
                or node.func.id not in ("mem8", "mem16", "mem32")):
            raise ValueError("only mem8/mem16/mem32 may be called")
    return compile(tree, "<breakpoint condition>", "eval")

def condition_namespace(regs, read_mem):
    """Names a condition may use: the registers, plus the three mem readers."""
    def reader(width):
        def rd(addr):
            data = read_mem(int(addr) & 0xFFFFFFFF, width)
            if not data or len(data) < width:
                raise ValueError(f"0x{int(addr) & 0xFFFFFFFF:08X} is not mapped")
            return int.from_bytes(data[:width], "little")
        return rd
    ns = dict(regs)
    ns.update(mem8=reader(1), mem16=reader(2), mem32=reader(4))
    ns["__builtins__"] = {}
    return ns

class Breakpoint:
    """One breakpoint or watchpoint, armed or not."""

    KINDS = ("execute", "write", "read", "access")
    # z/Z packet types. 0 is a software breakpoint, which under QEMU means an
    # entry in its own breakpoint list - it does NOT write 0xCC into guest
    # memory, so nothing is left behind if we die without cleaning up.
    ZKIND = {"execute": 0, "write": 2, "read": 3, "access": 4}

    def __init__(self, addr, kind="execute", size=1, condition="",
                 enabled=True, label=""):
        if kind not in self.KINDS:
            raise ValueError(f"unknown breakpoint kind {kind!r}")
        self.addr = int(addr) & 0xFFFFFFFF
        self.kind = kind
        self.size = 1 if kind == "execute" else int(size)
        self.condition = condition or ""
        self.enabled = bool(enabled)
        self.label = label or ""
        self.hits = 0
        self.skipped = 0                 # condition was false
        self.armed = False
        # Watchpoints logged by a "find what accesses this" window halt the
        # guest on every hit; the broker continues them again once the hit has
        # been recorded, so the game keeps running.
        self.auto_resume = False
        self.error = ""
        self._code = None
        self._code_src = None

    @property
    def zkind(self):
        return self.ZKIND[self.kind]

    def code(self):
        """Compile the condition lazily, caching until the text changes."""
        if not self.condition.strip():
            return None
        if self._code_src != self.condition:
            self._code = compile_condition(self.condition)
            self._code_src = self.condition
        return self._code

    def matches_stop(self, info, eip):
        """Is this the breakpoint the stub just reported?"""
        if info.get("watch") is not None:
            if self.kind == "execute":
                return False
            return self.addr <= info["watch"] < self.addr + self.size
        return self.kind == "execute" and eip == self.addr

    def describe(self):
        s = f"{self.kind} 0x{self.addr:08X}"
        if self.kind != "execute":
            s += f" [{self.size}]"
        if self.condition:
            s += f" if {self.condition}"
        return s

class DebugSession:
    """
    Run/stop control over the guest, with breakpoints and conditions.

    Deliberately synchronous and single-threaded: every method here is called
    from the Tk thread, and asynchronous stop replies are picked up by poll()
    on a Tk timer. The alternative - a worker thread owning the socket - was
    not used because Tk widgets may only be touched from the main thread, so a
    worker would need a queue in each direction for no gain: each request is
    sub-millisecond against a loopback socket.
    """

    STEP_LIMIT = 4000            # bounded fallback for step out

    def __init__(self, engine, read_fallback=None,
                 host=GDB_DEFAULT_HOST, port=GDB_DEFAULT_PORT):
        self.engine = engine
        self.host, self.port = host, port
        self.client = None
        self.stopped = False
        self.regs = {}
        self.stop_info = {}
        self.last_error = ""
        self.breakpoints = []
        self._temp = set()               # temp breakpoints for step over/out
        self._read_fallback = read_fallback
        self._pending = None             # "step" / "over" / "out" / "run"
        self._step_out_budget = 0
        # Events produced outside poll(): a real breakpoint hit that arrived
        # while we were halting the guest in order to edit a breakpoint.
        self._deferred = []
        # Nested breakpoint edits share one halt/resume instead of stopping and
        # starting the guest once per breakpoint.
        self._edit_depth = 0
        self._edit_halted = False

    # ---- connection ------------------------------------------------------
    @property
    def connected(self):
        return (self.client is not None and self.client.sock is not None
                and not getattr(self.client, "dead", False))

    def connect(self, break_on_attach=False):
        """
        Attach, and establish a KNOWN run state before doing anything else.

        This used to assume the guest was running. It often is not: starting
        the stub from xemu's Monitor can leave the VM paused, and then every
        piece of state in here is a lie - Run refuses to send `c` because it
        believes the guest is not halted, Break has nothing to interrupt, and
        arming a breakpoint times out because the caller thinks it must pause
        first when it is already paused. "The Run button does not resume the
        emulator" is that lie, seen from the outside.

        So: halt once, which the protocol always answers, then continue unless
        the user asked to attach paused. After this, self.stopped is fact.
        """
        c = GdbClient(self.host, self.port)
        c.connect()
        self.client = c
        self._deferred = []
        self._edit_depth = 0
        self.stopped = False
        self.regs = {}
        try:
            pkt = c.stop()
            if pkt:
                self._on_stop(pkt)
        except (GdbStubError, OSError) as exc:
            self.last_error = str(exc)
        self.arm_all()
        if not break_on_attach:
            self.cont()
        return True

    def disconnect(self):
        if self.client is None:
            return
        try:
            # force: whatever our flags say, nothing of ours may be left in the
            # stub after this returns.
            self.disarm_all(force=True)
            # Unconditionally, not `if self.stopped`. If our state tracking is
            # wrong the guest is left frozen with the tool gone - the worst
            # possible outcome, and unrecoverable without xemu's own controls.
            self.client.cont()
            # And say goodbye properly, so the stub drops anything we missed
            # and restarts the VM itself.
            self.client.detach()
        except (GdbStubError, OSError):
            pass
        self.client.close()
        self.client = None
        self.stopped = False
        self.regs = {}

    # ---- memory ----------------------------------------------------------
    def read_mem(self, va, n):
        """
        Read guest memory at a virtual address.

        Prefers the stub while halted, since that is guaranteed to be the
        state the registers describe. Falls back to the page-map read through
        /proc/<pid>/mem, which works whether or not the stub is attached.
        """
        if self.connected and self.stopped:
            try:
                return self.client.read_mem(va, n)
            except GdbStubError:
                pass
        if self._read_fallback is not None:
            return self._read_fallback(va, n)
        return b""

    def read_u32(self, va):
        data = self.read_mem(va, 4)
        return None if len(data) < 4 else int.from_bytes(data, "little")

    # ---- breakpoints -----------------------------------------------------
    def add(self, bp):
        self.breakpoints.append(bp)
        if self.connected and bp.enabled:
            self.arm(bp)
        return bp

    def remove(self, bp):
        # force: a deleted breakpoint must be gone from the stub even if our
        # armed flag says it was never there.
        self.disarm(bp, force=True)
        if bp in self.breakpoints:
            self.breakpoints.remove(bp)

    def find_exec(self, addr):
        for bp in self.breakpoints:
            if bp.kind == "execute" and bp.addr == addr:
                return bp
        return None

    def _pause_for_edit(self):
        """
        Halt the guest just long enough to change a breakpoint.

        The remote protocol is all-stop: while the guest runs, QEMU is not
        servicing the connection, so a Z packet sent to a running target gets
        no reply and the send times out - which is exactly the "Broken pipe" /
        "timed out" that arming a watchpoint produced. Real gdb halts before
        touching breakpoints too.

        Returns True if this call did the halting, so the caller knows whether
        to resume afterwards.
        """
        if not self.connected:
            return False
        self._edit_depth += 1
        if self._edit_depth > 1 or self.stopped:
            return False            # an outer edit already halted it
        pkt = self.client.stop()
        # FROM HERE WE OWE A CONTINUE.
        #
        # QEMU halts the moment it reads the interrupt byte, whether or not its
        # stop reply reaches us - and the reply can be missed, because it can be
        # consumed as a queued notification elsewhere or simply arrive after the
        # read timeout. This used to `return False` when no reply came, meaning
        # nobody resumed a guest that was already halted. That is the freeze:
        # arm a watchpoint, the emulator stops, and no button in the tool will
        # start it again because the tool does not believe it stopped it.
        #
        # So the interrupt itself, not its acknowledgement, is what creates the
        # obligation to resume.
        self.stopped = True
        if not pkt:
            self.regs = {}
            return True
        info = parse_stop_reply(pkt)
        try:
            self.regs = self.client.registers()
        except GdbStubError:
            self.regs = {}
        info["eip"] = self.regs.get("eip", 0)
        # The interrupt can collide with a genuine hit. Swallowing that would
        # lose the very event the user is waiting for, so it is queued and
        # poll() hands it over on the next tick - and the caller is told not to
        # resume, because a real hit is supposed to stay halted.
        for cand in self.breakpoints:
            if cand.enabled and cand.matches_stop(info, info["eip"]):
                cand.hits += 1
                info["bp"] = cand
                info["reason"] = f"{cand.kind} breakpoint"
                self._deferred.append(("stopped", info))
                return False        # a real hit stays halted
        return True

    def _resume_after_edit(self, we_halted):
        self._edit_depth = max(0, self._edit_depth - 1)
        if self._edit_depth:
            return
        if we_halted and self.connected and self.stopped:
            self.stopped = False
            self.regs = {}
            self._pending = "run"
            try:
                self.client.cont()
            except GdbStubError as exc:
                self.last_error = str(exc)

    def arm(self, bp):
        if not self.connected or bp.armed or not bp.enabled:
            return
        resume = False
        try:
            resume = self._pause_for_edit()
            self.client.set_break(bp.addr, bp.zkind, bp.size)
            bp.armed, bp.error = True, ""
        except (GdbStubError, OSError) as exc:
            bp.error = str(exc)
        finally:
            self._resume_after_edit(resume)

    def disarm(self, bp, force=False):
        """
        Remove a breakpoint from the stub.

        `force` sends the z packet even when bp.armed is False. That flag is
        our bookkeeping, and it goes stale: a reconnect clears it while the
        stub may still be holding the breakpoint, and an arm that half-failed
        leaves it False with the breakpoint in place. Deleting a breakpoint
        that then still fires is the worst kind of wrong, so teardown paths
        send the z regardless and ignore the error if there was nothing there.
        """
        if not self.connected:
            bp.armed = False
            return
        if not bp.armed and not force:
            return
        resume = False
        try:
            resume = self._pause_for_edit()
            self.client.clear_break(bp.addr, bp.zkind, bp.size)
        except (GdbStubError, OSError) as exc:
            self.last_error = str(exc)
        finally:
            bp.armed = False
            self._resume_after_edit(resume)

    def set_enabled(self, bp, on):
        bp.enabled = bool(on)
        if on:
            self.arm(bp)
        else:
            # force: a breakpoint switched off must stop firing even if the
            # armed flag has drifted.
            self.disarm(bp, force=True)

    def arm_all(self):
        for bp in self.breakpoints:
            self.arm(bp)

    def disarm_all(self, force=False):
        for bp in self.breakpoints:
            self.disarm(bp, force=force)
        self._clear_temps()

    def _add_temp(self, addr):
        if not self.connected:
            return
        try:
            self.client.set_break(addr, Breakpoint.ZKIND["execute"], 1)
            self._temp.add(addr)
        except GdbStubError as exc:
            self.last_error = str(exc)

    def _clear_temps(self):
        for addr in list(self._temp):
            if self.connected:
                self.client.clear_break(addr, Breakpoint.ZKIND["execute"], 1)
        self._temp.clear()

    # ---- run control -----------------------------------------------------
    def interrupt(self):
        """Halt the guest."""
        if not self.connected:
            return None
        pkt = self.client.stop()
        if pkt:
            return self._on_stop(pkt)
        # Some stubs answer the interrupt only on the next poll.
        self._pending = "break"
        return None

    def force_resume(self):
        """
        Send `c` whatever we believe the state to be.

        Our idea of running-versus-halted is an inference, and if it is wrong
        the guest stays frozen with the Run button refusing to do anything -
        which is worse than sending a redundant continue. Used by Run, by
        detach and by close, so there is always a way out.
        """
        if self.client is None or self.client.sock is None:
            return False
        self._clear_temps()
        self.stopped = False
        self.regs = {}
        self._pending = "run"
        try:
            self.client.cont()
            return True
        except (GdbStubError, OSError) as exc:
            self.last_error = str(exc)
            return False

    def cont(self):
        if not self.connected:
            return
        if not self.stopped:
            # Believed to be running already. Send it anyway: a spurious
            # continue is harmless, a missed one freezes the emulator.
            self.force_resume()
            return
        self._clear_temps()
        self.arm_all()
        self.stopped = False
        self.regs = {}
        self._pending = "run"
        self.client.cont()

    def step_into(self):
        if not self.connected or not self.stopped:
            return
        self.stopped = False
        self._pending = "step"
        self.client.step()

    def step_over(self):
        """
        Step one instruction, but treat a call as a single step.

        Implemented the way every debugger does it: a temporary breakpoint on
        the instruction after the call, then continue. That means a breakpoint
        inside the call still stops there, and a recursive call re-entering the
        same site stops early - both are the standard trade-off, not bugs.
        """
        if not self.connected or not self.stopped:
            return
        eip = self.regs.get("eip")
        if eip is None:
            return self.step_into()
        rows = disassemble_at(self.read_mem(eip, 16), eip, 1)
        addr, bhex, text = rows[0]
        size = len(bhex.split()) or 1
        mnem = text.split(" ")[0].lower()
        # rep-prefixed string ops are a loop in one instruction, so stepping
        # over them means running to the following instruction too.
        if mnem.startswith("call") or mnem.startswith("rep"):
            self._add_temp(eip + size)
            self.stopped = False
            self.regs = {}
            self._pending = "over"
            self.client.cont()
        else:
            self.step_into()

    def step_out(self):
        """
        Run to the return address of the current frame.

        Taken from [ebp+4], which assumes a standard frame. Optimised or
        frame-pointer-omitted code has no such frame and this will land
        somewhere wrong or not at all - there is no reliable alternative
        without unwind information, so the caller is told when the slot does
        not look like a return address.
        """
        if not self.connected or not self.stopped:
            return "not stopped"
        ebp = self.regs.get("ebp", 0)
        ret = self.read_u32(ebp + 4) if ebp else None
        if ret is None or ret < 0x1000:
            return ("no return address at [ebp+4] - this frame has no frame "
                    "pointer, so step out cannot find the caller")
        self._add_temp(ret)
        self.stopped = False
        self.regs = {}
        self._pending = "out"
        self.client.cont()
        return None

    def run_to(self, addr):
        if not self.connected:
            return
        self._add_temp(addr)
        if self.stopped:
            self.stopped = False
            self.regs = {}
            self._pending = "run"
            self.client.cont()

    def set_eip(self, addr):
        if not (self.connected and self.stopped):
            return False
        try:
            self.client.write_reg(GDB_X86_REGS.index("eip"), addr)
            self.regs = self.client.registers()
            return True
        except (GdbStubError, ValueError) as exc:
            self.last_error = str(exc)
            return False

    def set_register(self, name, value):
        if not (self.connected and self.stopped) or name not in GDB_X86_REGS:
            return False
        try:
            self.client.write_reg(GDB_X86_REGS.index(name), value)
            self.regs = self.client.registers()
            return True
        except GdbStubError as exc:
            self.last_error = str(exc)
            return False

    # ---- event pump ------------------------------------------------------
    def poll(self):
        """
        Called on a Tk timer. Returns a list of (event, payload) for the UI.

        Events: ("stopped", info), ("resumed", bp) for a condition miss,
        ("error", text), ("exited", info).
        """
        if not self.connected:
            return self._drain_deferred()
        out = self._drain_deferred()
        for _ in range(8):
            ev = self.poll_one()
            if ev is None:
                break
            out.append(ev)
        return out

    def poll_one(self):
        """
        Handle exactly ONE stub packet and return its event, or None.

        Events must be delivered one at a time, while the guest is still halted
        for that particular stop. Draining a batch and dispatching afterwards
        loses the context of every hit but the last: the registers, the stack
        and the code around EIP have all been overwritten by later stops, so a
        burst of ten watchpoint hits was logged as one, repeated.
        """
        if not self.connected:
            return None
        pkt = self.client.poll(0.005)
        if pkt is None:
            return None
        if pkt and pkt[0] in "WX":
            self.stopped = False
            return ("exited", parse_stop_reply(pkt))
        if not pkt or pkt[0] not in "TS":
            return None
        return self._on_stop(pkt)

    def _drain_deferred(self):
        out, self._deferred = self._deferred, []
        return out

    def _on_stop(self, pkt):
        info = parse_stop_reply(pkt)
        self.stopped = True
        self._clear_temps()
        try:
            self.regs = self.client.registers()
        except GdbStubError as exc:
            self.regs = {}
            self.last_error = str(exc)
        eip = self.regs.get("eip", 0)
        info["eip"] = eip
        was = self._pending
        self._pending = None

        bp = None
        for cand in self.breakpoints:
            if cand.enabled and cand.matches_stop(info, eip):
                bp = cand
                break

        # An unclaimed stop while a watchpoint is armed.
        #
        # Not every stub reports which watchpoint fired. QEMU usually appends
        # "watch:ADDR" to the stop reply, but not on every build or for every
        # watchpoint type, and without it matches_stop() cannot attribute the
        # stop to anything. That used to mean the hit was logged nowhere AND
        # the guest was never resumed - the emulator froze the instant the
        # watched address was touched, which is exactly the reported symptom.
        #
        # So when nothing claims a stop that we did not ask for, and exactly
        # one watchpoint is armed, it is attributed to that watchpoint. With
        # more than one armed it is left unattributed but STILL resumed, which
        # is the important half.
        if bp is None and was not in ("step", "over", "out", "break"):
            sole = self.sole_watchpoint()
            if sole is not None:
                bp = sole
                info["inferred"] = True
            else:
                info["unclaimed"] = True
        info["bp"] = bp

        # A stop from our own step or temp breakpoint is not a breakpoint hit.
        if bp is None:
            info["reason"] = {"step": "step", "over": "step over",
                              "out": "step out", "break": "paused",
                              "run": "stopped"}.get(was, "stopped")
            return ("stopped", info)

        if bp.condition.strip():
            ok, err = self.test_condition(bp)
            if err:
                info["reason"] = f"{bp.kind} breakpoint (condition error: {err})"
                bp.hits += 1
                return ("stopped", info)
            if not ok:
                bp.skipped += 1
                # Resume immediately; the user never sees this stop.
                self.stopped = False
                self.regs = {}
                self._pending = "run"
                try:
                    self.client.cont()
                except (GdbStubError, OSError) as exc:
                    self.last_error = str(exc)
                    return ("error", str(exc))
                return ("resumed", bp)
        bp.hits += 1
        info["reason"] = f"{bp.kind} breakpoint"
        return ("stopped", info)

    def sole_watchpoint(self):
        """The one armed auto-resuming watchpoint, or None if not exactly one."""
        found = None
        for bp in self.breakpoints:
            if bp.enabled and bp.kind != "execute" and bp.auto_resume:
                if found is not None:
                    return None
                found = bp
        return found

    def any_auto_resume(self):
        return any(bp.enabled and bp.auto_resume for bp in self.breakpoints)

    def test_condition(self, bp):
        """Returns (passed, error_text). An error counts as a stop, not a skip."""
        try:
            code = bp.code()
        except ValueError as exc:
            return True, str(exc)
        if code is None:
            return True, ""
        try:
            ns = condition_namespace(self.regs, self.read_mem)
            return bool(eval(code, ns)), ""
        except Exception as exc:                # noqa: BLE001 - user expression
            return True, f"{type(exc).__name__}: {exc}"

    def read_mem_paused(self, va, n):
        """
        Read guest memory over the stub, halting briefly if it is running.

        read_mem() only uses the stub while already halted and otherwise falls
        back to /proc, which is right for the common case. This is for the one
        that is not: recording a patch's original bytes, where a short read
        means the undo has nothing to put back and the patch becomes permanent
        until the game is restarted.
        """
        if not self.connected:
            return b""
        resume = False
        try:
            resume = self._pause_for_edit()
            return self.client.read_mem(va, n)
        except (GdbStubError, OSError) as exc:
            self.last_error = str(exc)
            return b""
        finally:
            self._resume_after_edit(resume)

    def write_mem(self, va, data):
        """
        Write guest memory THROUGH THE STUB, and why that matters.

        A write straight into /proc/<pid>/mem changes the bytes but tells QEMU
        nothing, so the JIT happily keeps executing the translated block it
        already has - the NOP appears to do nothing until something unrelated
        causes that block to be retranslated. The stub's M packet goes through
        QEMU's own debug write, which invalidates the translation, so the patch
        takes effect on the very next execution. This is why the same patch
        applied as a trainer code "works" and applied here seemed not to.
        """
        if not self.connected:
            return False
        resume = False
        try:
            resume = self._pause_for_edit()
            self.client.write_mem(va, bytes(data))
            return True
        except (GdbStubError, OSError) as exc:
            self.last_error = str(exc)
            return False
        finally:
            self._resume_after_edit(resume)

    # ---- introspection ---------------------------------------------------
    def call_stack(self, limit=32, in_image=None):
        """
        Walk the EBP chain. Returns [(frame_ebp, return_addr)].

        Frames are validated by requiring EBP to increase monotonically (the
        x86 stack grows down, so a caller's frame is always at a higher
        address) and the return address to be mapped. Without that check a
        garbage EBP produces an endless list of nonsense frames.
        """
        out = []
        ebp = self.regs.get("ebp", 0)
        seen = set()
        while ebp and len(out) < limit and ebp not in seen:
            seen.add(ebp)
            nxt = self.read_u32(ebp)
            ret = self.read_u32(ebp + 4)
            if ret is None or ret < 0x1000:
                break
            if in_image is not None and not in_image(ret):
                break
            out.append((ebp, ret))
            if nxt is None or nxt <= ebp:
                break
            ebp = nxt
        return out

    def stack_words(self, count=64):
        """Raw dwords from ESP upwards, as [(addr, value)]."""
        esp = self.regs.get("esp", 0)
        if not esp:
            return []
        data = self.read_mem(esp, count * 4)
        return [(esp + i * 4, int.from_bytes(data[i * 4:i * 4 + 4], "little"))
                for i in range(len(data) // 4)]

    def frame_slots(self, kind="locals", count=16):
        """
        Dwords of the current frame.

        Without debug information there are no named locals, so "locals" means
        the dwords between ESP and EBP (where a compiler puts them) and
        "parameters" means the dwords above the return address at [ebp+8]. Both
        are exactly what a disassembler shows as [ebp-0x4] and [ebp+0x8], which
        is the form the code view uses, so they line up by inspection.
        """
        ebp = self.regs.get("ebp", 0)
        esp = self.regs.get("esp", 0)
        if not ebp:
            return []
        out = []
        if kind == "locals":
            if not esp or esp > ebp:
                return []
            n = min(count, max(0, (ebp - esp) // 4))
            for i in range(n):
                addr = ebp - (i + 1) * 4
                if addr < esp:
                    break
                out.append((f"[ebp-0x{(i + 1) * 4:X}]", addr,
                            self.read_u32(addr)))
        else:
            for i in range(count):
                off = 8 + i * 4
                out.append((f"[ebp+0x{off:X}]", ebp + off,
                            self.read_u32(ebp + off)))
        return out

    def stub_threads(self):
        """
        Threads as the stub sees them.

        QEMU's gdbstub reports one thread per vCPU, not per guest OS thread,
        and the Xbox has a single CPU - so this is normally one entry. Guest
        threads have to be recovered from kernel structures instead; see
        scan_guest_threads().
        """
        if not self.connected:
            return []
        out = []
        for tid in self.client.threads():
            out.append((tid, self.client.thread_extra(tid)))
        return out

    def scan_guest_threads(self, pagemap, max_hits=64):
        """
        Find KTHREAD objects by their dispatcher header. UNVERIFIED heuristic.

        Every NT-family dispatcher object starts with a DISPATCHER_HEADER whose
        first byte is the object type, and ThreadObject is 6. That much is
        solid. What is *not* established here is the Xbox KTHREAD field layout,
        so instead of hardcoding an offset for StackBase/StackLimit this looks
        for any adjacent dword pair in the first 0x40 bytes that reads like a
        stack range, and reports the offset it found it at.

        The result is self-checking: the running thread's stack range must
        contain the current ESP. If exactly one candidate does, the heuristic
        found real thread objects. If none does, do not trust the list.
        """
        # valid is a property; calling it raises TypeError on a bool.
        if pagemap is None or not pagemap.valid:
            return []
        eng = self.engine
        esp = self.regs.get("esp", 0)
        hits = []
        # Kernel objects live in the kernel window, which is identity-mapped to
        # physical, so this can be scanned as a flat physical range.
        for region_lo, region_hi in ((0x80000000, 0x84000000),
                                     (0xD0000000, 0xD0100000)):
            for va in range(region_lo, region_hi, 0x1000):
                pa = pagemap.to_phys(va)
                if pa is None:
                    continue
                page = eng.read_mem(eng.xbox_ram_base + pa, 0x1000)
                if len(page) < 0x1000:
                    continue
                # Candidate offsets first, vectorised - a pure-Python loop over
                # 512 offsets per page across 16k pages is 8M iterations and
                # takes tens of seconds for what numpy does in a slice.
                if _HAVE_NUMPY:
                    col = np.frombuffer(page, dtype=np.uint8)[0:0x1000 - 0x40:8]
                    offsets = (np.nonzero(col == 6)[0] * 8).tolist()
                else:
                    offsets = [o for o in range(0, 0x1000 - 0x40, 8)
                               if page[o] == 6]
                for off in offsets:
                    size = page[off + 2]          # in dwords
                    if not 0x20 <= size <= 0x80:
                        continue
                    found = None
                    for k in range(4, 0x40, 4):
                        a = int.from_bytes(page[off + k:off + k + 4], "little")
                        b = int.from_bytes(page[off + k + 4:off + k + 8],
                                           "little")
                        if a <= b or (a >> 28) != (b >> 28) or (a >> 28) < 8:
                            continue
                        if 0x1000 <= a - b <= 0x100000:
                            found = (k, a, b)
                            break
                    if found is None:
                        continue
                    k, base, limit = found
                    hits.append({"kthread": va + off, "stack_base": base,
                                 "stack_limit": limit, "field_offset": k,
                                 "size": size * 4,
                                 "current": bool(esp and limit <= esp < base)})
                    if len(hits) >= max_hits:
                        return hits
        return hits
