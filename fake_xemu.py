"""
fake_xemu.py - a stand-in for xemu, for testing the attach path on Windows.

WHY
---
Verifying that the tools hook onto xemu needs xemu running a title, which needs
OpenGL 4.0, which a VM's virtual GPU does not provide. But nothing in the
attach path actually cares that the process is an emulator. It needs a process
named xemu.exe holding a committed read-write region of 64, 128 or 256 MB whose
contents look like Xbox RAM.

All of that can be faked, and faking it exercises the whole Windows chain for
real: CreateToolhelp32Snapshot finds the process, OpenProcess opens it,
VirtualQueryEx enumerates the region, ReadProcessMemory reads it back, and the
structural validator walks the page tables and finds the XBE magic.

WHAT IT BUILDS
--------------
A 128 MB region containing the minimum structure _looks_like_xbox_ram() checks:

    guest phys 0x0F000   page directory; PDE[0] -> page table at 0x20000
    guest phys 0x20040   PTE for guest virtual 0x10000 -> phys 0x30000
    guest phys 0x30000   'XBEH', where the XBE header would be

Guest physical N sits at host address base+N, exactly as it does in xemu, so
the offsets above are also the offsets the tools will read.

USAGE (from an elevated prompt, on Windows)
-------------------------------------------
    copy "%LOCALAPPDATA%\\Programs\\Python\\Python313\\python.exe" xemu.exe
    xemu.exe fake_xemu.py

The copy matters: the tools match on the PROCESS name, which is the name of the
running executable, not the name of the script. Running it with python.exe
would produce a process called python.exe and nothing would be found.

Leave it running, start the trainer or the cheat engine, and it should attach.
Ctrl+C to stop.
"""

import atexit
import ctypes
import ctypes.wintypes as wt
import os
import platform
import signal
import struct
import sys
import time

if platform.system() != "Windows":
    sys.exit("This is a Windows test helper.")

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04

# Retail Original Xbox RAM is 64 MB, so that is the default - it is what the
# tools will meet in practice. 128 MB is the devkit/debug configuration and
# xemu can be configured for it; 256 MB is accepted by the scan as well, so it
# is offered here to prove the size detection reports back whatever it finds
# rather than assuming one value.
RAM_SIZES_MB = (64, 128, 256)
DEFAULT_RAM_MB = 64

# Where the fake structures live, in GUEST PHYSICAL terms.
PD_BASE = 0x0F000                   # page directory
PT_BASE = 0x20000                   # page table for the first 4 MB
XBE_PHYS = 0x30000                  # where guest virtual 0x10000 lands
XBE_VIRT = 0x10000                  # where the XBE image is mapped

k32 = ctypes.windll.kernel32
k32.VirtualAlloc.restype = ctypes.c_void_p
k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                             wt.DWORD, wt.DWORD]
k32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wt.DWORD]


def build_ram(base):
    """Write the page tables and XBE magic into the freshly allocated region."""

    def poke(off, data):
        ctypes.memmove(base + off, data, len(data))

    # PDE index for a virtual address is bits 31:22. For 0x10000 that is 0, so
    # the entry sits at the very start of the directory. Bit 0 is Present; bit
    # 7 clear means this points at a page table rather than a 4 MB page.
    pde_index = (XBE_VIRT >> 22) & 0x3FF
    poke(PD_BASE + pde_index * 4, struct.pack('<I', PT_BASE | 0x03))

    # PTE index is bits 21:12 -> 0x10 for 0x10000. Present, writable.
    pte_index = (XBE_VIRT >> 12) & 0x3FF
    poke(PT_BASE + pte_index * 4, struct.pack('<I', XBE_PHYS | 0x03))

    # The XBE header the validator looks for.
    poke(XBE_PHYS, b'XBEH')

    # A little recognisable filler, so a manual look in the memory viewer shows
    # something other than a sea of zeros.
    poke(XBE_PHYS + 0x100, b'FAKE XEMU TEST REGION ' * 8)

    # A known 32-bit value at a known offset, for testing a scan by hand:
    # search for 1234567890 as int32 and it should turn up at 0x00100000.
    poke(0x100000, struct.pack('<i', 1234567890))


_ALLOC = {"base": None}


def release(reason=""):
    """
    Hand the region back. Safe to call more than once.

    Worth being clear about what this is and is not for. Windows destroys a
    process's entire private address space when it terminates, by any route -
    clean exit, unhandled exception, Task Manager kill, or a hard crash. The
    128 MB cannot outlive the process, and no cleanup code is required to make
    that true.

    What this does buy: the memory goes back at the moment of the signal
    rather than whenever the interpreter finishes unwinding, and the console
    says so, which matters when the whole point of the script is to be certain
    about what is and is not allocated while testing.
    """
    base = _ALLOC.get("base")
    if not base:
        return
    _ALLOC["base"] = None          # first, so a second call cannot double-free
    ok = k32.VirtualFree(ctypes.c_void_p(base), 0, MEM_RELEASE)
    print(f"\n[*] released 0x{base:016X}"
          f"{' (' + reason + ')' if reason else ''}"
          f"{'' if ok else ' - VirtualFree FAILED'}")


# Console close (the X button) and Ctrl+Break do not raise KeyboardInterrupt;
# without a handler the process is torn down with no chance to run Python code
# at all. HandlerRoutine: 0=Ctrl+C 1=Ctrl+Break 2=Close 5=Logoff 6=Shutdown.
_HANDLER_TYPE = ctypes.WINFUNCTYPE(wt.BOOL, wt.DWORD)


def _console_handler(event):
    release(f"console event {event}")
    return False                   # False = also run the default handler


_console_thunk = _HANDLER_TYPE(_console_handler)   # kept alive deliberately


def parse_size(argv):
    """
    Read the requested RAM size from the command line.

    Restricted to the three sizes the region scan accepts. Allowing an
    arbitrary size would just produce a process the tools ignore, which looks
    identical to a detection failure - the exact confusion this script exists
    to remove.
    """
    args = [a for a in argv[1:] if not a.lower().endswith(".py")]
    if not args:
        return DEFAULT_RAM_MB
    raw = args[0].lower().replace("mb", "").strip()
    try:
        mb = int(raw)
    except ValueError:
        sys.exit(f"[-] Not a number: {args[0]}\n"
                 f"    Usage: xemu.exe fake_xemu.py [{'|'.join(str(m) for m in RAM_SIZES_MB)}]")
    if mb not in RAM_SIZES_MB:
        sys.exit(f"[-] {mb} MB is not a size the tools look for.\n"
                 f"    The region scan only accepts "
                 f"{', '.join(str(m) for m in RAM_SIZES_MB)} MB, so any other\n"
                 f"    size would be ignored and look like a failure to attach.")
    return mb


def main():
    ram_mb = parse_size(sys.argv)
    ram_size = ram_mb * 1024 * 1024
    print(f"[*] pid {os.getpid()}, image {os.path.basename(sys.executable)}")
    if not os.path.basename(sys.executable).lower().startswith("xemu"):
        print("[!] This process is NOT named xemu.exe, so the tools will not")
        print("    find it. Copy python.exe to xemu.exe and run it with that.")

    base = k32.VirtualAlloc(None, ram_size, MEM_COMMIT | MEM_RESERVE,
                            PAGE_READWRITE)
    if not base:
        sys.exit(f"[-] VirtualAlloc failed: {ctypes.get_last_error()}")
    label = {64: "retail", 128: "devkit/debug"}.get(ram_mb, "")
    print(f"[+] allocated {ram_mb} MB{' (' + label + ')' if label else ''}"
          f" at 0x{base:016X}")

    _ALLOC["base"] = base
    # Belt and braces across the exit paths Python can see: normal return,
    # sys.exit, and an unhandled exception all run atexit handlers; SIGTERM and
    # SIGINT do not, so they are hooked separately.
    atexit.register(release, "atexit")
    k32.SetConsoleCtrlHandler(_console_thunk, True)
    for sig in (signal.SIGINT, signal.SIGTERM, getattr(signal, "SIGBREAK", None)):
        if sig is not None:
            try:
                signal.signal(sig, lambda s, f: (release(f"signal {s}"),
                                                 sys.exit(0)))
            except (ValueError, OSError):
                pass

    build_ram(base)
    print(f"[+] page directory at guest phys 0x{PD_BASE:X}")
    print(f"[+] guest virtual 0x{XBE_VIRT:X} -> phys 0x{XBE_PHYS:X} = 'XBEH'")
    print(f"[+] test value 1234567890 (int32) at guest phys 0x00100000")
    print()
    print(f"    Expect: attaches, {ram_mb} MB, ram_region_verified True.")
    print("    Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        release("Ctrl+C")
    finally:
        # Covers an unhandled exception on the way out too. release() is
        # idempotent, so overlapping with atexit costs nothing.
        release("exit")


if __name__ == "__main__":
    main()
