# Xemu toolchain — split into module folders

Each script is now a small launcher with its implementation in a folder beside
it. Drop both scripts and both folders in the same directory and run them
exactly as before.

```
xemu_cheat_engine.py        launcher
xemu_engine_lib/            16 modules
xemu_cheats_trainer.py      launcher
xemu_trainer_lib/           13 modules
xemu_privs.py               shared privilege probing / ownership reclaim
fake_xemu.py                test helper - fake attach target
win_probe.py                test helper - Windows attach diagnostic
```

Each launcher does `sys.path.insert(0, <its own directory>)`, so the folders
travel with the scripts. No install step, no `PYTHONPATH`, no package manager.

---

## Module map

### `xemu_engine_lib/`

| Module | Lines | Contents |
|---|---:|---|
| `prelude` | 170 | Shared imports, numpy gate, Windows ctypes definitions |
| `engine_core` | 1,235 | `XemuTrainerEngine` — attach, RAM read/write, scanning, freeze loop |
| `regions` | 123 | Xbox region map, XBE section parsing, `describe_address` |
| `ui_widgets` | 505 | Wheel binding, menus, clipboard fix, geometry, monitors |
| `gdb_client` | 353 | `GdbClient`, `GdbStubError`, `disassemble_at` |
| `func_index` | 449 | `FunctionIndex` — symbol/RTTI/string cross-referencing |
| `sendtables` | 422 | `SendTableIndex` |
| `debug_session` | 941 | `DebugSession`, `Breakpoint`, condition compiler |
| `pagemap` | 597 | `XboxPageMap`, `PointerMap`, chain scanning + verification |
| `trainer_window` | 3,597 | `TrainerWindow` |
| `gdb_broker` | 554 | `GdbBroker`, `GdbWatchWindow` |
| `disasm_window` | 2,316 | `DisassemblyWindow` |
| `memviewer` | 1,101 | `TabbedMemoryViewer` |
| `code_patch` | 326 | `CodePatchWindow` — JIT-safe assembly patches **(new)** |
| `online_guard` | 454 | Online-play detection and code whitelist **(new, unwired)** |

### `xemu_trainer_lib/`

| Module | Lines | Contents |
|---|---:|---|
| `prelude` | 58 | Shared imports, Windows ctypes definitions |
| `mem` | 285 | `XemuMemory` — attach, raw read/write, region validation |
| `ui_widgets` | 261 | Wheel binding, menus, clipboard fix |
| `pagemap` | 114 | `XboxPageMap` (on-demand walker) |
| `cheat_tree` | 87 | Node construction and traversal primitives |
| `gdb_lite` | 143 | `GdbLite` |
| `tree_ops` | 117 | Enable state, sorting, normalising, counting |
| `codes` | 1,228 | `CheatEngine` — all code types, ASM patch journal, switch state |
| `cheatfiles` | 343 | Per-game `cheats/` and `patches/` file database |
| `config` | 277 | `Config` |
| `app` | 1,975 | `CheatManagerApp` |
| `online_guard` | 454 | Online-play detection and code whitelist **(new)** |

Dependency direction is one-way in both packages, and there are **no import
cycles**. `ui_*` depends on logic; logic never imports UI.

---

## Cheat code types

The type is the top nibble of the first word. `codes.py` carries the
authoritative version of this table in its module docstring.

| | | | |
|---|---|---|---|
| `0` | 8-bit constant write | `8` | 8-bit constant write (virtual) |
| `1` | 16-bit constant write | `9` | 16-bit constant write (virtual) |
| `2` | 32-bit constant write | `A` | 32-bit constant write (virtual) |
| `3` | Increment / Decrement | `B` | Boolean operation |
| `4` | 32-bit constant serial write | `C` | 32-bit do-all-following-if-equal |
| `5` | Copy bytes | `D` | Do multi-lines if conditional |
| `6` | Pointer write (physical or virtual) | `E` | Conditional on/off switch |
| `7` | *free* | `F` | Hook code — reserved, unimplemented |

Type 6 selects its address space with a flag byte in the header line — `00`
physical, `01` virtual — which is what allowed the old virtual-pointer type 7 to
be retired. Type E reuses type D's field layout exactly and differs only in
treating the condition as an edge, so a D code becomes a button toggle by
changing one nibble.

Both retired types are still *consumed* with their old line counts rather than
skipped as one line: an unhandled multi-line code leaves its tail to be read as
fresh codes, and `0000000C 000001E3` is a type-0 write into the interrupt vector
table.

---

## Verification

Nothing was rewritten. Every definition was moved by line span and the result
checked four ways.

| Check | Engine | Trainer |
|---|---|---|
| All modules compile | PASS | PASS |
| Top-level definitions preserved | 41/41 | 31/31 |
| Definition source byte-identical | ALL MATCH | ALL MATCH |
| Duplicated across modules | none | none |
| Every module imports | 13/13 | 10/10 |
| Global name references resolve | PASS | PASS |
| Functional equivalence vs original | 19/19 identical | |

Functional equivalence ran identical inputs through the original and the split
side by side in one interpreter: `describe_address`, `parse_xbe_sections`, the
region tables, the breakpoint condition compiler (including confirming it still
*rejects* `__import__` and `open`), evaluated conditions, `parse_raw_code_text`,
`parse_text`, `is_asm_name`, and the full tree-operation surface.

---

## Two bugs found and fixed during the split

Both would have failed at *runtime*, not at import — the kind that only shows up
when you happen to hit the code path.

**1. `_HAVE_NUMPY` disappeared.** `from .prelude import *` silently skips
underscore-prefixed names, so four modules lost it. Fixed by giving `prelude.py`
an `__all__` computed at runtime:

```python
__all__ = [_n for _n in dir() if not _n.startswith('__')]
```

Runtime, not hard-coded, so the platform-conditional names still appear only
where they did originally. Confirmed by executing `prelude.py` with
`platform.system()` patched to return `"Windows"`: `ctypes`, `wintypes`,
`PROCESSENTRY32`, `PROCESS_ALL_ACCESS`, `MEM_COMMIT`, `PAGE_READWRITE` and
`TH32CS_SNAPPROCESS` all reach a star-import consumer, and `_HAVE_NUMPY` is
carried through.

**2. The launcher broke on Linux.** The generated launcher initially wrote
`from xemu_engine_lib.prelude import ctypes, os, platform, sys`. In the original,
`ctypes` is only referenced *inside* the `if platform.system() == "Windows"`
branch, which short-circuits on Linux — so the name never has to exist there.
Naming it explicitly turned that into a hard `ImportError` at startup. Both
launchers now use a star import, matching the original's conditional
availability.

---

## Known-benign findings (documented so they don't look like bugs later)

**Static analysis reports 26 "unresolved" names.** Two categories, both checked:

- *Windows-only* (`ctypes`, `wintypes`, `PROCESSENTRY32`, `PROCESS_ALL_ACCESS`,
  `MEM_COMMIT`, `PAGE_READWRITE`, `TH32CS_SNAPPROCESS`). Absent on Linux in the
  **original** too. Proven to resolve on Windows by the simulation above.
- *Closure variables* (`after1`, `after2`, `lb_parent`, `remove_off`,
  `show_code`, `on_virt_toggle`, `refresh_view`, `render_highlights`, `state`,
  `virt_var`). Running the same analyzer against the unmodified original flags
  the identical ten names — they are limitations of the analyzer, not
  regressions.

**16 of 582 callables compile to different bytecode.** Traced to its root: CPython
compiles `X.method(...)` differently depending on whether `X` is *defined* in the
module or *imported* into it.

```
defined in module : LOAD_GLOBAL (P)  /  LOAD_ATTR (NULL|self + on_demand)
imported by name  : LOAD_GLOBAL (NULL + P)  /  LOAD_ATTR (on_demand)
```

Splitting a file necessarily converts local definitions into imports, so this is
inherent to the operation. Both sequences were executed against the same inputs:
identical return values, identical exceptions, identical arguments received by
the callee.

This count was 153 before a fix. Each module now repeats the prelude's plain
`import` statements, which restores the compile-time binding for `struct`, `os`,
`re`, `tk` and friends. Only the Windows `if` block is *not* repeated — that
keeps `PROCESSENTRY32` a single shared class rather than one per module.

---

## Platform support

| Platform | State |
|---|---|
| Linux | Supported. Needs `PTRACE_MODE_ATTACH` — root, `CAP_SYS_PTRACE`, or `ptrace_scope=0`. See `xemu_privs.py`. |
| Windows | Supported. Needs Administrator. Cheat Engine additionally needs `pip install numpy`. |
| macOS | **Not supported.** Detected and reported rather than failing silently. Needs a `task_for_pid()` / `mach_vm_*` backend. |

Both GUIs, the game database, and the full attach chain are confirmed working
on Windows 10. See `README_CHANGES.md` for what was verified and how.

---

## Test helpers

`fake_xemu.py` presents a process named `xemu.exe` holding a 64/128/256 MB
region containing a valid page directory, a PTE for guest virtual `0x10000`, and
the `XBEH` magic. It exercises the entire attach path with no emulator and no
GPU — which matters, because xemu needs OpenGL 4.0 and a VM's virtual GPU does
not provide it.

```
copy "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" xemu.exe
xemu.exe fake_xemu.py          # 64 MB retail; also accepts 128 or 256
```

The copy matters: the tools match on the *process* name, not the script name.

`win_probe.py` walks the same four steps the tools take — process search,
`OpenProcess`, region scan, `ReadProcessMemory` plus the structural check — and
reports each separately, then dumps every large committed region with its
protection and type. When someone reports "Waiting for Xemu...", this turns one
ambiguous message into a specific failure.

It also found the `PROCESSENTRY32` bug: a deliberately independent
implementation disagreed with the tool, which three rounds of static review had
not managed.

---

## Deliberately unchanged

Written when the split was purely mechanical. Behaviour *has* since changed —
see `README_CHANGES.md` — but these specific items are still as found:

- **`XboxPageMap.__init__` in `xemu_trainer_lib/pagemap.py` is the pre-numpy
  version** — benchmarked at 10,854 ms versus 28 ms for the engine's numpy
  version on a synthetic 64 MB Xbox RAM image, with identical output. It is
  currently dead code: the trainer only calls `XboxPageMap.on_demand(...)` and
  never constructs `XboxPageMap(dump)`. A landmine, not an active fire.
- **The two page maps handle cache staleness differently.** The engine uses a
  `CACHE_TTL` timer; the trainer probes a single PDE covering the XBE image.
  The trainer's comment cites measurements behind that choice. Pick one
  deliberately when unifying — do not let a merge decide silently.
- **`vt` at `engine_core` is assigned and never read** (was line 8516 in the
  monolith). Left in place so it does not muddy a pure-move diff.
- **`clear_asm_journal` has a statement before its docstring**, so the string is
  not a docstring at all and simply evaluates to nothing. Harmless, but it will
  confuse whoever reads it next.

The larger unification — one shared core behind both front-ends, removing the
three drifted parallel implementations of process attach, page translation, and
the GDB protocol — is described in the earlier plan document and is a separate
piece of work.
# Xemu-Cheat-Engine-And-Trainer-
