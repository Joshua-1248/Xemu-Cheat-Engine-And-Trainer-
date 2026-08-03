"""
online_guard.py - refuse to apply cheats while xemu is playing online.

WHAT THIS IS FOR
----------------
Cheating in single player is the point of these tools. Cheating against other
people is not, and the Original Xbox online scene is small and volunteer-run:
Insignia, XLink Kai, private LAN tunnels. A trainer that works in an online
match is a liability to those communities.

So: while xemu holds a connection that looks like online play, cheat writes are
refused. Codes that patch a game's own online checks are exempt, because those
are compatibility fixes rather than advantages - see ONLINE_SAFE_TAG below.

WHAT THIS IS NOT
----------------
Not anti-cheat. This is an open-source Python program; anyone who wants to
defeat it can delete this file. It stops the casual case - someone who loads a
trainer out of habit and wanders into a match - and it states the project's
intent plainly. It cannot stop a determined cheater and does not pretend to.

Anyone relying on this for competitive integrity should not.

HOW DETECTION WORKS
-------------------
The emulated Xbox has no separate network stack from the host's point of view:
xemu's own process opens the sockets. So the check is "does the xemu process
hold a connection that indicates online play", answered from the OS rather than
from anything inside the guest.

Three signals, any of which counts:

  1. An established TCP connection from xemu to a PUBLIC address. LAN and
     loopback are excluded so that offline play, local tunnels to a LAN
     partner, and xemu's own gdbstub do not trip it.
  2. Traffic on ports the console network stack uses - 3074 is the classic
     Xbox Live port, and XLink Kai's engine listens on 34522/34523.
  3. An XLink Kai engine process running on this machine at all, since Kai
     bridges traffic on xemu's behalf and xemu may only ever talk to
     localhost.

Signal 1 is the load-bearing one. 2 and 3 catch cases where the connection is
UDP or proxied and so is harder to see as an established TCP session.

KNOWN LIMITS, stated rather than hidden
---------------------------------------
  * A game played entirely over a LAN tunnel that keeps all traffic inside
    RFC1918 space will not be detected. Excluding private ranges is
    deliberate - without it, every user behind a normal router trips the guard
    permanently - but it is a real gap.
  * Detection is polled, not instant. There is a window of a second or two
    after a match starts.
  * It cannot tell "in an online match" from "sitting in an online menu". It
    errs toward refusing.
"""

import hashlib
import os
import platform
import socket
import struct
import time

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"

# Exemptions are keyed on the CODE CONTENT, not the name.
#
# A name tag would be self-applied: anyone wanting a cheat online just renames
# it. Hashing the actual code lines means the exemption travels with the code,
# a rename achieves nothing, and the allowed set is something the project
# curates rather than something each user grants themselves.
#
# The tag below still exists, but only as a hint in the UI - it is NOT
# sufficient on its own. See is_whitelisted().
ONLINE_SAFE_TAG = "[ONLINE-SAFE]"

WHITELIST_FILE = "online_whitelist.txt"

# Format, one entry per line:
#     <sha256-prefix>  <title-id or *>  # free-text description
# Lines starting with # are comments. The hash is of the normalised code list;
# use fingerprint() to generate one.
_WHITELIST_HEADER = """\
# Codes permitted while xemu is in an online match.
#
# Entries are hashes of the code content, so renaming a cheat does not grant
# an exemption and editing one revokes it. Generate a line with:
#
#     python -c "from xemu_trainer_lib.online_guard import fingerprint; \\
#                print(fingerprint([(0x801F6B23, 1)]))"
#
# Only connectivity fixes belong here - patches that restore access to a
# service, in the spirit of a PS2 DNAS patch. Nothing that changes how the
# game plays against other people.
#
# <hash>  <title-id or *>  # description
"""


def fingerprint(codes):
    """
    A stable hash of a cheat's code lines.

    Normalised so cosmetic differences do not change the result: each code is
    reduced to its (command, value) pair as integers, ordered as written, and
    rendered in a fixed format. Reordering the lines DOES change the hash, on
    purpose - order can change what a code sequence does.
    """
    parts = []
    for entry in (codes or []):
        try:
            cmd, val = entry[0], entry[1]
        except (TypeError, IndexError):
            continue
        parts.append(f"{int(cmd) & 0xFFFFFFFF:08X}{int(val) & 0xFFFFFFFF:08X}")
    if not parts:
        return ""
    return hashlib.sha256(":".join(parts).encode()).hexdigest()[:16]

# Ports that indicate console networking regardless of peer address.
#   3074      Xbox Live / Xbox system link
#   34522-3   XLink Kai engine
#   9050      Insignia's tunnel port (also used by others; weak signal alone)
ONLINE_PORTS = {3074, 34522, 34523}

# Process names that mean a LAN-tunnelling bridge is running on this machine.
TUNNEL_PROCESSES = ("kaiengine", "kaiEngine", "xlink", "insignia")

POLL_INTERVAL = 3.0        # seconds between checks; cheap, but not free


# ---------------------------------------------------------------------------
# Address classification
# ---------------------------------------------------------------------------
def _is_private_v4(ip):
    """
    True for addresses that cannot be a public online-play peer.

    Excluding these is what keeps the guard from firing on every user behind a
    router. It is also the main gap: a purely-LAN match is invisible here.
    """
    try:
        a, b = (int(x) for x in ip.split('.')[:2])
    except (ValueError, IndexError):
        return True                      # unparseable: do not fire on it
    if a == 10 or a == 127 or a == 0:
        return True
    if a == 192 and b == 168:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 169 and b == 254:            # link-local
        return True
    if a == 100 and 64 <= b <= 127:      # CGNAT
        return True
    if a >= 224:                         # multicast / reserved
        return True
    return False


# ---------------------------------------------------------------------------
# Linux: /proc/<pid>/fd -> socket inodes -> /proc/net/{tcp,udp}
# ---------------------------------------------------------------------------
def _linux_sockets(pid):
    """Every (local_port, remote_ip, remote_port, established) for one pid."""
    inodes = set()
    fd_dir = f"/proc/{pid}/fd"
    try:
        for fd in os.listdir(fd_dir):
            try:
                link = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if link.startswith("socket:["):
                inodes.add(link[8:-1])
    except OSError:
        return []
    if not inodes:
        return []

    out = []
    for proto in ("tcp", "udp", "tcp6", "udp6"):
        try:
            with open(f"/proc/{pid}/net/{proto}") as fh:
                next(fh, None)
                for line in fh:
                    parts = line.split()
                    if len(parts) < 10 or parts[9] not in inodes:
                        continue
                    try:
                        lport = int(parts[1].split(':')[1], 16)
                        rhex, rport_hex = parts[2].split(':')
                        rport = int(rport_hex, 16)
                        state = parts[3]
                    except (ValueError, IndexError):
                        continue
                    if proto.endswith('6'):
                        # Only the v4-mapped case is worth decoding; a native
                        # v6 peer is reported as non-private via its port only.
                        rip = _v6_to_display(rhex)
                    else:
                        rip = socket.inet_ntoa(struct.pack("<I", int(rhex, 16)))
                    out.append((lport, rip, rport, state == "01"))
        except (OSError, StopIteration):
            continue
    return out


def _v6_to_display(hexstr):
    """v4-mapped v6 addresses come back as dotted quads; others as ''. """
    try:
        raw = bytes.fromhex(hexstr)
        if len(raw) == 16 and raw[:12] == b'\x00' * 10 + b'\xff\xff':
            return socket.inet_ntoa(raw[12:])
    except ValueError:
        pass
    return ""


# ---------------------------------------------------------------------------
# Windows: GetExtendedTcpTable / GetExtendedUdpTable, filtered by pid
# ---------------------------------------------------------------------------
def _windows_sockets(pid):
    import ctypes
    import ctypes.wintypes as wt

    TCP_TABLE_OWNER_PID_ALL = 5
    UDP_TABLE_OWNER_PID = 1
    AF_INET = 2
    MIB_TCP_STATE_ESTAB = 5

    class MIB_TCPROW_OWNER_PID(ctypes.Structure):
        _fields_ = [("dwState", wt.DWORD), ("dwLocalAddr", wt.DWORD),
                    ("dwLocalPort", wt.DWORD), ("dwRemoteAddr", wt.DWORD),
                    ("dwRemotePort", wt.DWORD), ("dwOwningPid", wt.DWORD)]

    class MIB_UDPROW_OWNER_PID(ctypes.Structure):
        _fields_ = [("dwLocalAddr", wt.DWORD), ("dwLocalPort", wt.DWORD),
                    ("dwOwningPid", wt.DWORD)]

    out = []
    iphlp = ctypes.windll.iphlpapi

    def fetch(func, table_class, row_class, level):
        size = wt.DWORD(0)
        func(None, ctypes.byref(size), False, AF_INET, level, 0)
        buf = ctypes.create_string_buffer(size.value)
        if func(buf, ctypes.byref(size), False, AF_INET, level, 0) != 0:
            return []
        n = struct.unpack_from("I", buf, 0)[0]
        rows = []
        off = ctypes.sizeof(wt.DWORD)
        for _ in range(n):
            rows.append(row_class.from_buffer_copy(
                buf.raw[off:off + ctypes.sizeof(row_class)]))
            off += ctypes.sizeof(row_class)
        return rows

    for row in fetch(iphlp.GetExtendedTcpTable, None,
                     MIB_TCPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL):
        if row.dwOwningPid != pid:
            continue
        rip = socket.inet_ntoa(struct.pack("<I", row.dwRemoteAddr))
        out.append((socket.ntohs(row.dwLocalPort & 0xFFFF), rip,
                    socket.ntohs(row.dwRemotePort & 0xFFFF),
                    row.dwState == MIB_TCP_STATE_ESTAB))

    for row in fetch(iphlp.GetExtendedUdpTable, None,
                     MIB_UDPROW_OWNER_PID, UDP_TABLE_OWNER_PID):
        if row.dwOwningPid != pid:
            continue
        out.append((socket.ntohs(row.dwLocalPort & 0xFFFF), "", 0, False))
    return out


# ---------------------------------------------------------------------------
# Tunnel processes
# ---------------------------------------------------------------------------
def _tunnel_running():
    """Name of a LAN-tunnel process if one is running, else None."""
    try:
        if IS_LINUX:
            for pid in os.listdir("/proc"):
                if not pid.isdigit():
                    continue
                try:
                    with open(f"/proc/{pid}/comm") as fh:
                        name = fh.read().strip()
                except OSError:
                    continue
                low = name.lower()
                if any(t.lower() in low for t in TUNNEL_PROCESSES):
                    return name
        elif IS_WINDOWS:
            import ctypes
            import ctypes.wintypes as wt

            class PE32(ctypes.Structure):
                _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
                            ("th32ProcessID", wt.DWORD),
                            ("th32DefaultHeapID",
                             ctypes.POINTER(ctypes.c_ulong)),
                            ("th32ModuleID", wt.DWORD),
                            ("cntThreads", wt.DWORD),
                            ("th32ParentProcessID", wt.DWORD),
                            ("pcPriClassBase", wt.LONG),
                            ("dwFlags", wt.DWORD),
                            ("szExeFile", ctypes.c_char * 260)]

            k32 = ctypes.windll.kernel32
            snap = k32.CreateToolhelp32Snapshot(0x2, 0)
            if snap == -1:
                return None
            pe = PE32()
            pe.dwSize = ctypes.sizeof(PE32)
            ok = k32.Process32First(snap, ctypes.byref(pe))
            try:
                while ok:
                    name = pe.szExeFile.decode(errors="replace")
                    low = name.lower()
                    if any(t.lower() in low for t in TUNNEL_PROCESSES):
                        return name
                    ok = k32.Process32Next(snap, ctypes.byref(pe))
            finally:
                k32.CloseHandle(snap)
    except Exception:                                          # noqa: BLE001
        pass
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
class OnlineGuard:
    """
    Polls for signs of online play and reports whether cheats should be held.

    Results are cached for POLL_INTERVAL so the freeze loop can ask on every
    pass without the cost. Failure to determine anything is treated as OFFLINE:
    a guard that blocks cheats because it could not read /proc would be worse
    than one that occasionally misses.
    """

    def __init__(self, whitelist_dir=None):
        self.enabled = True
        self._last_check = 0.0
        self._online = False
        self._reason = ""
        self._whitelist = {}          # hash -> (titleid, description)
        self.whitelist_path = None
        if whitelist_dir:
            self.load_whitelist(whitelist_dir)

    # -- whitelist ---------------------------------------------------------
    def load_whitelist(self, directory):
        """
        Read the permitted-code list. A missing file simply means none.

        Deliberately not created on demand: an empty file the user can append
        to looks like an invitation. If the project ships no exemptions, the
        honest state is no file.
        """
        self.whitelist_path = os.path.join(directory, WHITELIST_FILE)
        self._whitelist = {}
        try:
            with open(self.whitelist_path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.split("#")[0].strip()
                    if not line:
                        continue
                    bits = line.split()
                    if not bits:
                        continue
                    h = bits[0].lower()
                    tid = bits[1].upper() if len(bits) > 1 else "*"
                    self._whitelist[h] = tid
        except OSError:
            pass
        return len(self._whitelist)

    def is_whitelisted(self, codes, titleid=None):
        """
        Whether this exact code content is permitted online.

        The title id must match too, unless the entry says '*'. The same bytes
        can mean entirely different things in two games, so an exemption
        granted for one should not carry to another.
        """
        fp = fingerprint(codes)
        if not fp or fp not in self._whitelist:
            return False
        allowed = self._whitelist[fp]
        if allowed == "*":
            return True
        return str(titleid or "").upper() == allowed

    def check(self, pid, force=False):
        """(online, reason). Cheap to call repeatedly."""
        if not self.enabled or not pid:
            return False, ""
        now = time.time()
        if not force and (now - self._last_check) < POLL_INTERVAL:
            return self._online, self._reason

        self._last_check = now
        self._online, self._reason = self._evaluate(pid)
        return self._online, self._reason

    def _evaluate(self, pid):
        try:
            socks = (_windows_sockets(pid) if IS_WINDOWS
                     else _linux_sockets(pid) if IS_LINUX else [])
        except Exception:                                      # noqa: BLE001
            return False, ""

        for lport, rip, rport, established in socks:
            if lport in ONLINE_PORTS or rport in ONLINE_PORTS:
                return True, f"console network port {lport or rport} in use"
            if established and rip and not _is_private_v4(rip):
                return True, f"connected to {rip}:{rport}"

        tunnel = _tunnel_running()
        if tunnel:
            return True, f"{tunnel} is running"
        return False, ""

    # -- policy ------------------------------------------------------------
    @staticmethod
    def has_safe_tag(name):
        """
        Whether the name carries the ONLINE-SAFE hint.

        A hint only. Users can rename anything, so this never grants an
        exemption by itself - it exists so the UI can show which cheats are
        *meant* to be online-safe, and so a tagged-but-unlisted cheat is
        visibly a mistake rather than silently blocked.
        """
        return ONLINE_SAFE_TAG.lower() in str(name or "").lower()

    def blocked(self, pid, cheat_name, codes=None, titleid=None):
        """
        (blocked, reason) for one specific cheat.

        Order matters. Online state is established first, so an exemption has
        no effect offline and cannot be used to smuggle anything past a check
        that was not going to fire anyway.
        """
        online, reason = self.check(pid)
        if not online:
            return False, ""
        if self.is_whitelisted(codes, titleid):
            return False, ""
        return True, reason
