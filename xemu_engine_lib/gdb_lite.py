"""Minimal GDB stub client used for ASM patches.

Extracted verbatim from xemu_cheats_trainer.py.
"""
from .prelude import *  # noqa: F401,F403
import os, sys, time, struct, platform, threading, re, json, configparser
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog


GDB_HOST_DEFAULT = "127.0.0.1"

GDB_PORT_DEFAULT = 1234

class GdbLite:
    """Just enough of the remote protocol to write memory and resume."""

    def __init__(self, host=GDB_HOST_DEFAULT, port=GDB_PORT_DEFAULT,
                 timeout=1.0):
        self.host, self.port, self.timeout = host, port, timeout
        self.sock = None
        self.buf = b""
        self.no_ack = False
        self.dead = False

    # ---- plumbing -----------------------------------------------------
    def connect(self):
        import socket
        self.sock = socket.create_connection((self.host, self.port),
                                             timeout=self.timeout)
        self.sock.settimeout(self.timeout)
        self.dead = False
        try:
            if self._cmd("QStartNoAckMode") == "OK":
                self.no_ack = True
        except Exception:                                   # noqa: BLE001
            pass
        return self

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None
        self.dead = True

    @property
    def alive(self):
        return self.sock is not None and not self.dead

    def _send(self, payload):
        data = payload.encode()
        pkt = b"$" + data + b"#" + f"{sum(data) & 0xFF:02x}".encode()
        try:
            self.sock.sendall(pkt)
        except OSError:
            self.dead = True
            raise
        if not self.no_ack:
            try:
                self._recv(1)
            except Exception:                               # noqa: BLE001
                pass        # a missing ack is not worth failing a write over

    def _recv(self, n=4096):
        if self.buf:
            out, self.buf = self.buf[:n], self.buf[n:]
            return out
        data = self.sock.recv(n)
        if not data:
            self.dead = True
            raise OSError("connection closed by xemu")
        return data

    def _read_packet(self):
        while True:
            while b"$" not in self.buf:
                self.buf += self._recv()
            self.buf = self.buf[self.buf.index(b"$") + 1:]
            while b"#" not in self.buf:
                self.buf += self._recv()
            end = self.buf.index(b"#")
            payload = self.buf[:end]
            while len(self.buf) < end + 3:
                self.buf += self._recv()
            self.buf = self.buf[end + 3:]
            if not self.no_ack:
                try:
                    self.sock.sendall(b"+")
                except OSError:
                    self.dead = True
            return payload.decode("latin1")

    def _cmd(self, payload):
        self._send(payload)
        # Stop notifications can be queued ahead of the reply; set them aside.
        for _ in range(64):
            pkt = self._read_packet()
            if pkt[:1] in ("T", "S", "W", "X"):
                continue
            return pkt
        return ""

    # ---- the three operations we need ---------------------------------
    def stop(self):
        """Halt the guest. Having sent this we OWE a continue - see cont()."""
        try:
            self.sock.sendall(b"\x03")
        except OSError:
            self.dead = True
            return False
        try:
            self._read_packet()
        except Exception:                                   # noqa: BLE001
            pass        # QEMU halts on the byte whether or not we see the reply
        return True

    def cont(self):
        try:
            self._send("c")
        except Exception:                                   # noqa: BLE001
            pass

    def read_mem(self, va, n):
        r = self._cmd(f"m{va:x},{n:x}")
        try:
            return bytes.fromhex(r) if r and not r.startswith("E") else b""
        except ValueError:
            return b""

    def write_mem(self, va, data):
        r = self._cmd(f"M{va:x},{len(data):x}:{bytes(data).hex()}")
        return r == "OK"

    def detach(self):
        try:
            self._cmd("D")
        except Exception:                                   # noqa: BLE001
            pass
        self.close()

