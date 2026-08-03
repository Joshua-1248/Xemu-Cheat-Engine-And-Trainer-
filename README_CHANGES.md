# What changed in this round

Cross-platform support, four bugs that made Windows unusable, three that broke
gdbstub patching, and two new subsystems.

---

## 1. Windows support actually works now

Both tools ran on Windows before this round only in the sense that the window
opened. Attaching was impossible, for a reason nobody had found.

### `PROCESSENTRY32` was missing a field

`tlhelp32.h` defines:

```c
DWORD     dwSize;
DWORD     cntUsage;
DWORD     th32ProcessID;
ULONG_PTR th32DefaultHeapID;   /* this was absent */
DWORD     th32ModuleID;
...
CHAR      szExeFile[MAX_PATH];
```

Both preludes omitted `th32DefaultHeapID` and declared `th32ModuleID` as a
`c_void_p` in its place. That put `szExeFile` at offset **40 instead of 44**.
`Process32First` fills the buffer using the real layout, so the code read the
process name from four bytes early — garbage, every time, so `"xemu.exe"` never
matched.

**No Windows user could attach with either tool, ever.** Verified fixed:
`sizeof=304, szExeFile@44, th32ProcessID@8`, matching the header.

Worth recording *how* this was found, because three rounds of static audit read
straight past it. It surfaced only when a separately written diagnostic
(`win_probe.py`) declared the struct correctly and disagreed with the tool. A
struct that looks plausible does not announce itself; an independent
implementation that disagrees does.

### `ReadProcessMemory` failures looked like zeroed memory

The Windows read path ignored both the `BOOL` return and `bytes_read`, handing
back the buffer regardless. `ReadProcessMemory` is all-or-nothing — one
unreadable page anywhere fails the whole call — so a failed read was
indistinguishable from a region full of zeros.

During a full scan that meant the 128 MB dump came back empty and the UI
reported "0 results" with no error anywhere, while the identical scan worked on
Linux (`/proc/pid/mem` does partial reads happily).

Now: fast path unchanged when the full read succeeds; on failure it retries in
64 KB chunks, so one bad page costs a page rather than the whole request.
Unreadable regions stay zero, matching the Linux short-read behaviour.
`WriteProcessMemory` likewise checks its return, and on failure lifts page
protection with `VirtualProtectEx`, retries, and restores the original
protection immediately.

### The RAM region scan was a guess

Three defects in one function, in both packages:

- `mbi.Protect == PAGE_READWRITE` was an exact match, so any region carrying an
  extra flag was skipped.
- `cur += mbi.RegionSize` advanced from the *query* address. `VirtualQueryEx`
  rounds the query down to a page boundary and measures `RegionSize` from
  there, so the walk could skip regions or stall.
- Nothing confirmed the chosen region was Xbox RAM. It took the largest of a
  plausible size, which on Windows can easily be a JIT cache or GPU staging
  buffer.

The third is now answered structurally rather than by size. `_looks_like_xbox_ram`
walks the guest page directory at physical `0xF000`, follows one PDE and one PTE
for guest virtual `0x10000`, and expects `XBEH` at the resulting physical
address. Three reads, and essentially nothing but real Xbox RAM satisfies the
chain.

Tested against two real 128 MB xemu dumps: accepts the correct base, rejects a
base off by a single page, rejects junk, and picks the genuine region over a
*larger* decoy — which the old "take the biggest" logic got wrong.

The fallback matters as much as the check: before a title loads there is no XBE
at `0x10000`, so verification cannot pass. In that case it takes the largest
candidate exactly as before and records `ram_region_verified = False`.
Attaching at the dashboard still works.

Both platforms now share one chooser. The two page maps drifted apart because a
fix reached only one copy; this heuristic is the same shape of thing.

### `EnumDisplayMonitors` callback had the wrong signature

`MonitorEnumProc` is `BOOL CALLBACK(HMONITOR, HDC, LPRECT, LPARAM)`. `LPARAM` is
a pointer-sized *integer*, but it was declared `ctypes.c_double`, making ctypes
read the fourth argument from a floating-point register (XMM3 on x64) instead of
the integer one (R9). The callback ignores that argument so it limped along, but
it is a calling-convention mismatch on every menu popup.

Also bound the callback thunk to a name before passing it — an inline `cb(_cb)`
creates a temporary whose refcount can hit zero, freeing the trampoline while
`EnumDisplayMonitors` is still calling into it.

### Text files were opened without an encoding

Python defaults text mode to the *locale* encoding: UTF-8 on Linux, **cp1252 on
Windows**. Demonstrated both halves of the failure:

- reading a UTF-8 file as cp1252 → `UnicodeDecodeError: 'charmap' codec can't
  decode byte 0x81`
- writing non-ASCII as cp1252 → `UnicodeEncodeError`

With 736 games, titles like *Pokémon XD* are enough to trigger it.

`cheatfiles.py` already did this correctly, which is what made it stand out:
`config.py` was *writing* the INI as UTF-8 while three of its readers used the
locale default. On Linux those agree; on Windows the freeze interval, sort mode
and JIT-safe setting silently reset to defaults on every launch, swallowed by a
`try/except`.

Fixed in eight places, with `ensure_ascii=False` on the JSON writers so names
stay readable. `os.replace` was already used for atomic saves, which is correct —
`os.rename` fails on Windows when the destination exists.

### macOS now says so instead of failing silently

Every platform branch was Linux-or-Windows with a no-op fallthrough, so on macOS
reads returned zeros and writes vanished with no error — the app looked attached
and did nothing. Both tools now detect it and report it in the status bar.

`xemu_privs.require_memory_access` also told Mac users to obtain *Administrator
rights on Windows*, because `elevated()` probes the Windows admin API and
swallows the `AttributeError`. It now names the platform first.

Real macOS support needs `task_for_pid()` and `mach_vm_*` instead of `/proc`,
plus code signing and disabled SIP. That is a backend, not a patch, and belongs
after the `core/process.py` extraction — one class instead of 36 branches.

### numpy is a hard requirement, and now says so

`_HAVE_NUMPY` read like a graceful-degradation flag but is not one: `pagemap.py`
has 76 unguarded `np.` uses, plus 23 in `trainer_window.py` and 19 in
`engine_core.py`. Without numpy the engine imports cleanly and then dies with a
`NameError` on the first address translation.

The engine now fails at startup with a dialog containing the install commands in
**copyable fields** with Copy buttons — a message you have to retype from a
screenshot is barely better than none. Console output too, for terminal
launches. The interpreter name comes from `sys.executable`, so it prints
`python.exe` on Windows and `python3` on Linux, and the Debian `apt` alternative
is offered because those systems increasingly reject a bare `pip install`.

Deliberately **not** a pure-Python fallback: the equivalent page-table walker
benchmarks at 10,854 ms versus 28 ms, so a fallback would "work" while freezing
for eleven seconds on every rebuild.

The trainer needs no numpy and says so in the dialog.

---

## 2. A live Linux bug: `self.pid` was a string

`_find_linux` took the pid from `os.listdir('/proc')`, which yields strings.
`is_alive()` then called `os.kill(self.pid, 0)`, which raises
`TypeError: 'str' object cannot be interpreted as an integer` — swallowed by a
bare `except`.

**`is_alive()` returned `False` on every call on Linux.** The 2-second watchdog
had been tearing down and rebuilding the connection continuously: rescanning
`/proc`, re-parsing `maps`, and briefly clearing `xbox_ram_base` each time —
which is very likely what produced the periodic `None + int` traceback bursts.
Windows was unaffected; `PROCESSENTRY32` gives an int.

---

## 3. gdbstub patching: three bugs, one root cause

xemu paused on every `[ASM]` toggle and never resumed. The mechanism is a QEMU
subtlety worth writing down, because all three bugs come back to it:

```c
static void gdb_read_byte(uint8_t ch) {
    if (runstate_is_running()) {
        /* when the CPU is running, we cannot do anything except stop
           it when receiving a char */
        vm_stop(RUN_STATE_PAUSED);
    }
```

**Any byte arriving while the guest is running re-pauses it and is discarded.**

1. **`c` then `D`.** The code resumed with a continue, then sent detach — which
   arrived while running, re-paused, and was thrown away. The socket closed with
   xemu paused and nothing left to resume it. `D` both detaches *and* resumes, so
   when releasing the connection it must be sent **instead of** the continue,
   while the guest is still stopped.

2. **The same trap one level up.** Batching the connection across a block still
   sent `c` after each line, so the block's closing `D` arrived while running.
   Multi-patch blocks are exactly what activating a game triggers. The guest now
   stays halted for the whole block and is resumed exactly once.

3. **A no-op detach on the error path.** The `except` set `self.gdb = None`, and
   the `finally` called `gdb_close()` — which only acts *when `self.gdb` is still
   set*. Any error meant the detach never happened. The `finally` now detaches
   the local client object directly.

### And a UI freeze

The freeze thread calls `execute_block` continuously while the UI calls it again
on every toggle, sharing one socket with no mutual exclusion. Their packets
interleave, the RSP protocol desyncs, and reads block until timeout — on the Tk
main thread, so the window stops responding.

An `RLock` now serialises the entire halt→write→verify→resume sequence.
`stop()` is inside the `try` so a failure still releases the lock, and the
release lives in the `finally`. Stress-tested with four threads, 800 calls and a
client failing 40% of the time: no double-stops, no deadlock, guest never left
stopped.

### JIT-safe patching was switched off

`gdb_lite.py` and the whole stub write path already existed, gated behind
`self.gdb_enabled = False`. Every `[ASM]` patch silently took the raw-write
fallback and did nothing under TCG. Now on by default, persisted as
`gdb_patching`, with a **JIT-safe patches** checkbox and a status indicator that
speaks up only when a patch is actually in play.

The socket is released after each write, because xemu's stub accepts one
connection and holding it would lock the Cheat Engine out.

### Patches auto-flush without a naming convention

`_asm_active` was gated on a name ending in `[ASM]`, so a patch called "60 FPS"
took the raw path and never executed. `all_game_nodes` now tags every block in
the patches section — a patch is by definition a code edit. Tagged there because
it is the one call both the freeze loop and the restore pass go through, so they
cannot disagree.

`list()` around `walk_cheats` in that function is load-bearing: it is a
generator, and tagging by iterating it left it exhausted, so `all_game_nodes`
returned nothing and every cheat silently disabled. Caught in testing.

---

## 4. Code type consolidation: 6, 7, D and E

### Type 6 now covers all pointer writes

Type 6 (physical, one dereference) and type 7 (virtual, N dereferences) differed
only in which address space the base and intermediate pointers live in. That is
a flag, not a code type.

```
6aaaaaaa vvvvvvvv    a = 28-bit base, v = value
XXSS00NN oooooooo    XX = 00 physical base, 01 virtual base
                     SS = size (00=8, 01=16, 02=32)
                     NN = offset count (1-8)
oooooooo oooooooo    offsets 2..N, two per line
```

**Backward compatible with old type 6.** Those wrote `00SS0000 oooooooo`, which
parses as physical with a count of 0 → clamped to one offset. Exactly the old
behaviour, so existing type 6 codes need no rewriting. Only type 7 codes change,
and **multi-level physical chains work now**, which the old type 6 could not do.

Verified against a synthetic memory model: old type 7 and new type 6 produce
byte-identical writes to the correct target, all three sizes are correct, and
line accounting holds for N=1 through 8.

**A bug the unification introduced, found and fixed.** The disabled-code skip
path had `elif code_type in (0x4, 0x5, 0x6): idx += 2`. Correct when type 6 was
always two lines; wrong now that it can be six. A multi-offset type 6 inside a
*false* conditional would skip two lines and leak its offset lines into the
parser as fresh codes. It would have worked fine right up until the condition
stopped matching.

### Type 7 removed

Handler and both dispatch entries deleted. `7` is now free.

It is still **consumed** with its old line count rather than skipped as one
line. Falling through to the default `idx += 1` would leave an old code's header
to be read as a fresh code, and `00020002 0000021C` is a type-0 write of `0x1C`
to physical `0x20002`.

### Type E retired, then reassigned as an on/off switch

E was the same conditional as D with the fields laid out differently. Verified
field by field across 200,000 random codes: the 28-bit offset, 16-bit compare,
3-bit test, 8/16-bit selector and 8-bit line count are all expressible in D.
`_typeD` documents the conversion.

E is now a **conditional on/off switch**, modelled on Gecko's `CC` code, reusing
D's field layout exactly — a D code becomes a toggle by changing one nibble.

```
Eaaaaaaa NNiTsvvv    i = initial state (bit 23): 0 off, 1 on
                     all other fields identical to D
```

The difference is that E treats the condition as an **edge**: the switch flips
on a false → true transition, and the guarded lines run while it is on, whether
or not the condition still holds.

```
E00A6B24 03080020    press X (mask 0x20) to toggle the next 3 lines
0012C4E0 00000063
0012C4E4 00000063
0012C4E8 00000063
```

That edge is what makes a button press a toggle rather than a hold. A "press X
to toggle" written with D would flicker on and off sixty times a second for as
long as the button was down.

State is held per (block id, line index), so two switches in one cheat are
independent and a switch survives the freeze loop's next pass. It is cleared
with the ASM journal when a game is deactivated — a switch left on would apply
its guarded lines the instant the next game attached, with no button pressed and
nothing on screen to explain it. An unreadable address holds the switch where it
is and keeps guarding on its current state; a failed read is not a button
release.

Tested across a press/hold/release sequence, the initial-state bit, switch
independence, and the unreadable-address path.

**Anything still using the old type E semantics must be converted to D first.**
Those codes will now behave as switches, which is not what they meant.

### Current type map

```
0  8-bit constant write            8  8-bit constant write (virtual)
1  16-bit constant write           9  16-bit constant write (virtual)
2  32-bit constant write           A  32-bit constant write (virtual)
3  Increment / Decrement           B  Boolean operation
4  32-bit constant serial write    C  32-bit do-all-following-if-equal
5  Copy bytes                      D  Do multi-lines if conditional
6  Pointer write (phys or virt)    E  Conditional on/off switch
7  ** FREE **                      F  Hook code - reserved, unimplemented
```

Physical (0/1/2) and virtual (8/9/A) constant writes were left as separate
types deliberately. They are single-line codes with nowhere to put a flag byte,
the address field cannot spare a bit, and changing their format would invalidate
every existing cheat for no functional gain — unlike the 6/7 merge, which was
free and added multi-level physical chains.

## 5. New: online guard

Cheating in single player is the point. Cheating against other people is not,
and the Original Xbox online scene is small and volunteer-run.

While xemu holds a connection that indicates online play, cheat writes are
refused. Three signals: an established TCP connection to a **public** address;
console network ports (3074 Xbox Live, 34522/3 XLink Kai); or an XLink Kai
engine process running at all, since Kai proxies traffic and xemu may only ever
talk to localhost.

Gated at `execute_block`, not in the UI — a UI gate only stops the button, not
the freeze thread re-applying an already-enabled cheat.

**Exemptions are keyed on code content, not names.** A name tag would be
self-applied; anyone wanting a cheat online just renames it. `fingerprint()`
hashes the normalised `(command, value)` pairs, and `online_whitelist.txt` maps
those hashes to title ids. Renaming achieves nothing, editing a code revokes its
exemption, reordering revokes it, and the title id must match unless the entry
says `*`.

Intended only for connectivity fixes — the Xbox equivalent of a PS2 DNAS patch.

### Stated limits

- A pure-LAN match is **not** detected. Excluding private ranges is required or
  every user behind a router trips it permanently. Real gap.
- Detection is polled, so there is a second or two after a match starts.
- **This is not anti-cheat.** It is an open-source Python program; anyone who
  wants to defeat it can delete the file. It stops someone who loads a trainer
  out of habit and wanders into a match, and states the project's intent. Nobody
  should rely on it for competitive integrity.

**The Cheat Engine is not yet gated** — `online_guard.py` is present in
`xemu_engine_lib/` but unwired. Its freeze loop, address table and Code Patches
window are still open. Since it is the more capable tool, this is the larger
half of the feature and remains outstanding.

---

## 6. New: Code Patches window (engine)

Assembly-level edits applied through the gdbstub so the JIT sees them. Hex bytes
at a guest virtual address, apply/revert, JSON save/load.

Original bytes are captured on first apply and **never from the saved file** — a
stale "original" written over a different build corrupts code rather than
restoring it. Loading therefore clears the enabled flags: a saved patch was
applied to a guest that no longer exists.

Every apply reads back and compares, because a write to ROM or unmapped memory
can be accepted and do nothing, and silently-not-applied is the worst failure
mode here.

---

## 7. Address table: multi-row selection (engine)

Ctrl+click toggles, Shift+click extends, Ctrl+A selects all (suppressed while
focus is in an Entry). Bulk delete, set-value, freeze/unfreeze, move-to-group.

Selected rows may not share a type, so each is packed against its own type
rather than packing once; failures are collected and reported rather than
aborting the batch. `e[4]` is updated alongside the write, or the freeze thread
stomps the new value on its next pass.

---

## 8. Smaller fixes

- **Shutdown timers.** `destroy()` never cancelled the pending `after`
  callbacks, so `update_table_view` and `_check_connection` fired against
  half-destroyed widgets. The memviewer's `on_close` likewise never cancelled
  each tab's `live_id`.
- **`live_loop` rescheduled after `refresh_view()`**, so one exception
  permanently ended live mode. Now reschedules first.
- **Detached-state guards.** `update_table_view` returns early when `pid` or
  `xbox_ram_base` is `None`; the memviewer wraps its `/proc` open. Together
  these stop the traceback floods when xemu exits.
- **`"monospace"` font** is an X11 alias Windows Tk does not resolve — it fell
  back to a proportional font and misaligned every hex column. Now `"Courier"`.
- **The trainer's INI was a bare relative name**, resolved against the cwd.
  Launching from a shortcut silently created a second empty database, and since
  `base_dir()` derives `cheats/` and `patches/` from it, the whole library
  appeared to vanish. Now anchored to the install directory.

---

## Testing notes

Most of this round was verified by execution rather than review, which is what
found the `PROCESSENTRY32` bug after static audit missed it three times.

Two helpers came out of it and are worth keeping in the repo:

- **`fake_xemu.py`** — allocates a 64/128/256 MB region containing a valid page
  directory, a PTE for guest virtual `0x10000`, and `XBEH`, in a process named
  `xemu.exe`. Exercises the entire attach chain with no emulator and no GPU,
  which matters because xemu needs OpenGL 4.0 and a VM's virtual GPU does not
  provide it. Defaults to 64 MB (retail).
- **`win_probe.py`** — walks the same four steps the tools take and reports each
  separately, then dumps every large committed region with protection and type.
  When a user reports "Waiting for Xemu...", this turns one ambiguous message
  into a specific failure.

Confirmed working on Windows 10: both GUIs build, the 736-game database loads,
the numpy dialog renders with working Copy buttons, elevation is detected and
reported, and the full attach chain succeeds —
`Attached! Xbox Retail (64MB RAM) | PID: 7864` with `ram_region_verified: True`.

### Still untested

Attaching to **real xemu on Windows**. The chain is proven against `fake_xemu.py`,
which by construction presents the layout the scan expects. Whether Windows xemu
allocates guest RAM the same way — `MEM_PRIVATE` at exactly one of the three
sizes — is unverified. `win_probe.py` answers it in one run if a user reports a
failure.
