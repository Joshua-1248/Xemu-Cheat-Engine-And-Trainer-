"""GDB remote-serial-protocol client for the Xemu stub.

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
from .ui_widgets import GDB_DEFAULT_HOST, GDB_DEFAULT_PORT  # noqa: F401


GDB_X86_REGS = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
                "eip", "eflags", "cs", "ss", "ds", "es", "fs", "gs")

class GdbStubError(Exception):
    pass

class GdbClient:
    """Minimal GDB remote serial protocol client - enough for watchpoints."""

    def __init__(self, host=GDB_DEFAULT_HOST, port=GDB_DEFAULT_PORT,
                 timeout=2.0):
        self.host, self.port, self.timeout = host, port, timeout
        self.sock = None
        self.buf = b""
        self.no_ack = False
        # Stop replies that arrived while we were waiting for the answer to
        # something else. Sampling registers on a timer makes this a real race:
        # the guest can hit a breakpoint between our interrupt and its reply,
        # and mistaking a stop notification for register data would desync the
        # protocol for the rest of the session.
        self.pending = []
        # Set once the socket is unusable, so callers stop pretending it works.
        self.dead = False
        # Every packet in and out, for diagnosing behaviour that cannot be
        # reproduced here - which stub a build actually implements, whether a
        # continue was acknowledged, whether a stop reply names a watchpoint.
        # Cheap (a bounded deque of short strings) so it is always on.
        import collections
        self.trace = collections.deque(maxlen=4000)
        self._last_send = ""

    # ---- transport -------------------------------------------------------
    def connect(self):
        import socket
        self.sock = socket.create_connection((self.host, self.port),
                                             timeout=self.timeout)
        self.sock.settimeout(self.timeout)
        # QStartNoAckMode removes the +/- handshake on every packet. Optional;
        # if the stub declines we simply keep acking.
        try:
            if self._cmd("QStartNoAckMode") == "OK":
                self.no_ack = True
        except GdbStubError:
            pass
        return self

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    @staticmethod
    def _checksum(data: bytes) -> int:
        return sum(data) & 0xFF

    def _log(self, direction, text):
        try:
            self.trace.append((time.time(), direction, text[:200]))
        except Exception:                                   # noqa: BLE001
            pass

    def _send(self, payload: str):
        data = payload.encode()
        pkt = b"$" + data + b"#" + f"{self._checksum(data):02x}".encode()
        self._log(">", payload)
        self._last_send = payload
        try:
            self.sock.sendall(pkt)
        except OSError as exc:
            # BrokenPipeError, ConnectionReset and friends are OSError, not
            # GdbStubError, so they used to sail straight past every
            # `except GdbStubError` in this file and out through a Tk callback
            # as a traceback. Everything the socket can raise is funnelled into
            # GdbStubError here, and the client is marked dead so nothing tries
            # to keep using it.
            self.dead = True
            raise GdbStubError(f"connection lost: {exc}") from None
        if not self.no_ack:
            self._read_ack()

    def _read_ack(self):
        while True:
            try:
                b = self._recv_some(1)
            except socket.timeout:
                # A missing ack after a resume is not fatal: the guest is off
                # and running and simply has nothing more to say. Killing the
                # connection here left the session looking attached while every
                # later command failed.
                self._log("!", "no ack")
                if self._last_send[:1] in ("c", "s", "C", "S", "v"):
                    return b"+"
                self.dead = True
                raise GdbStubError(
                    "the stub did not acknowledge - it usually means the guest "
                    "is running and not servicing the connection") from None
            if b in (b"+", b"-"):
                return b
            # Stray notification; keep looking for the ack.

    def _recv_some(self, n=4096) -> bytes:
        if self.buf:
            out, self.buf = self.buf[:n], self.buf[n:]
            return out
        try:
            data = self.sock.recv(n)
        except (socket.timeout, BlockingIOError):
            raise                      # the caller distinguishes these
        except OSError as exc:
            self.dead = True
            raise GdbStubError(f"connection lost: {exc}") from None
        if not data:
            self.dead = True
            raise GdbStubError("connection closed by xemu")
        return data

    def _read_packet(self, timeout=None) -> str:
        """Read one $...#xx packet. Returns the payload."""
        pkt = self._read_packet_raw(timeout)
        self._log("<", pkt)
        return pkt

    def _read_packet_raw(self, timeout=None) -> str:
        import socket
        old = self.sock.gettimeout()
        if timeout is not None:
            self.sock.settimeout(timeout)
        try:
            while b"$" not in self.buf:
                self.buf += self._recv_some()
            start = self.buf.index(b"$")
            while True:
                end = self.buf.find(b"#", start)
                if end != -1 and len(self.buf) >= end + 3:
                    break
                self.buf += self._recv_some()
            payload = self.buf[start + 1:end]
            self.buf = self.buf[end + 3:]
            if not self.no_ack:
                self.sock.sendall(b"+")
            return payload.decode(errors="replace")
        except (socket.timeout, BlockingIOError):
            raise GdbStubError("timeout waiting for the stub")
        finally:
            self.sock.settimeout(old)

    # Commands whose own reply IS a stop notification. For everything else a
    # T/S/W/X packet is an asynchronous stop and has to be set aside, not
    # returned as if it were the answer.
    _STOP_CMDS = ("c", "s", "C", "S", "vCont")

    def _cmd(self, payload: str, timeout=None) -> str:
        self._send(payload)
        if payload.startswith(self._STOP_CMDS):
            return self._read_packet(timeout)
        # Bounded only so a broken stub cannot spin here forever; the real
        # limit is the socket timeout. A burst of watchpoint hits can queue
        # dozens of stop notifications ahead of a command reply, and giving up
        # after a fixed handful meant register reads failed exactly when hits
        # were arriving fastest - the hits were then logged with no EIP and
        # silently dropped.
        for _ in range(1024):
            pkt = self._read_packet(timeout)
            if pkt[:1] in ("T", "S", "W", "X"):
                self.pending.append(pkt)
                continue
            return pkt
        return ""

    # ---- operations ------------------------------------------------------
    def stop(self):
        """Halt the guest. Ctrl-C in the protocol is a bare 0x03 byte."""
        self.sock.sendall(b"\x03")
        try:
            return self._read_packet(timeout=self.timeout)
        except GdbStubError:
            return ""

    def registers(self):
        """Return {name: value} for the x86-32 general registers."""
        raw = self._cmd("g")
        if raw.startswith("E") or len(raw) < len(GDB_X86_REGS) * 8:
            raise GdbStubError(f"could not read registers ({raw[:16]})")
        out = {}
        for i, name in enumerate(GDB_X86_REGS):
            word = raw[i * 8:(i + 1) * 8]
            # Each register is little-endian hex, so byte-swap to get a value.
            out[name] = int.from_bytes(bytes.fromhex(word), "little")
        return out

    def read_mem(self, addr, length):
        r = self._cmd(f"m{addr:x},{length:x}")
        if r.startswith("E"):
            raise GdbStubError(f"read at 0x{addr:08X} failed ({r})")
        return bytes.fromhex(r)

    # Watchpoint kinds, per the RSP spec.
    WRITE, READ, ACCESS = 2, 3, 4

    def set_watchpoint(self, addr, length=4, kind=WRITE):
        r = self._cmd(f"Z{kind},{addr:x},{length:x}")
        if r == "":
            raise GdbStubError("the stub does not support watchpoints")
        if r != "OK":
            raise GdbStubError(f"could not set watchpoint ({r})")

    def clear_watchpoint(self, addr, length=4, kind=WRITE):
        try:
            self._cmd(f"z{kind},{addr:x},{length:x}")
        except GdbStubError:
            pass

    def cont(self):
        self._send("c")

    def detach(self):
        """
        Tell the stub we are leaving, the way real gdb does.

        This was missing, and it is the difference between "detached" and
        "vanished". On `D`, QEMU removes every breakpoint it is holding for us
        and restarts the VM. Just closing the socket relies on the stub
        noticing, and if it does not, the guest keeps hitting breakpoints that
        nothing is listening for - it halts, nobody answers, and the emulator
        cannot be unpaused because it is waiting for a debugger that has gone.
        """
        try:
            self._cmd("D")
        except (GdbStubError, OSError):
            pass

    def wait_stop(self, timeout):
        """Wait for a stop reply. Returns the raw packet, or None on timeout."""
        try:
            return self._read_packet(timeout=timeout)
        except GdbStubError:
            return None

    # ---- breakpoints, stepping, threads ---------------------------------
    # Z/z types: 0 software breakpoint, 1 hardware breakpoint, 2 write
    # watchpoint, 3 read watchpoint, 4 access watchpoint. Prefer 0 for code -
    # QEMU keeps software breakpoints in its own list instead of patching 0xCC
    # into guest memory, so there is no 4-breakpoint debug-register limit and
    # nothing left behind in RAM if this process dies mid-session.
    SW_BREAK, HW_BREAK = 0, 1

    def set_break(self, addr, kind=SW_BREAK, length=1):
        r = self._cmd(f"Z{kind},{addr:x},{length:x}")
        if r == "":
            raise GdbStubError("the stub does not support this breakpoint type")
        if r != "OK":
            raise GdbStubError(f"could not set breakpoint at 0x{addr:08X} ({r})")

    def clear_break(self, addr, kind=SW_BREAK, length=1):
        try:
            self._cmd(f"z{kind},{addr:x},{length:x}")
        except GdbStubError:
            pass

    def step(self):
        """Single-step one instruction. The stop reply arrives via poll()."""
        self._send("s")

    def write_mem(self, addr, data):
        r = self._cmd(f"M{addr:x},{len(data):x}:{bytes(data).hex()}")
        if r != "OK":
            raise GdbStubError(f"write at 0x{addr:08X} failed ({r})")

    def write_reg(self, index, value):
        """Write one register by its index in GDB_X86_REGS."""
        hexval = (int(value) & 0xFFFFFFFF).to_bytes(4, "little").hex()
        r = self._cmd(f"P{index:x}={hexval}")
        if r != "OK":
            raise GdbStubError(f"could not write register {index} ({r or 'unsupported'})")

    def threads(self):
        """Thread IDs the stub knows about. QEMU reports one per vCPU."""
        out = []
        try:
            pkt = self._cmd("qfThreadInfo")
            while pkt and pkt[0] == "m":
                out += [t for t in pkt[1:].split(",") if t]
                pkt = self._cmd("qsThreadInfo")
        except GdbStubError:
            pass
        return out

    def thread_extra(self, tid):
        """qThreadExtraInfo returns a hex-encoded description, or nothing."""
        try:
            r = self._cmd(f"qThreadExtraInfo,{tid}")
            if r and not r.startswith("E") and len(r) % 2 == 0:
                return bytes.fromhex(r).decode("latin1", "replace")
        except (GdbStubError, ValueError):
            pass
        return ""

    def select_thread(self, tid):
        try:
            self._cmd(f"Hg{tid}")
        except GdbStubError:
            pass

    def poll(self, timeout=0.01):
        """
        Non-blocking check for an asynchronous stop reply.

        A partial packet stays in self.buf across a timeout, so calling this
        repeatedly on a Tk timer cannot split or lose a reply.
        """
        if self.sock is None:
            return None
        if self.pending:
            return self.pending.pop(0)
        try:
            return self._read_packet(timeout=max(0.001, timeout))
        except GdbStubError:
            return None

def disassemble_at(code: bytes, addr: int, count=4):
    """Disassemble guest code if capstone is available; describe bytes if not."""
    try:
        import capstone
    except ImportError:
        return [(addr, code[:8].hex(" "), "(pip install capstone to decode)")]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    out = []
    for ins in md.disasm(code, addr):
        out.append((ins.address, ins.bytes.hex(" "),
                    f"{ins.mnemonic} {ins.op_str}".strip()))
        if len(out) >= count:
            break
    return out or [(addr, code[:8].hex(" "), "(undecodable)")]

