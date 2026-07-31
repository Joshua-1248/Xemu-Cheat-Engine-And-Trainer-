# Xemu toolchain — split into module folders

Each script is now a small launcher with its implementation in a folder beside
it. Drop both scripts and both folders in the same directory and run them
exactly as before.

```
xemu_cheat_engine.py        launcher (32 lines)
xemu_engine_lib/            13 modules
xemu_cheats_trainer.py      launcher (29 lines)
xemu_trainer_lib/           10 modules
```

Each launcher does `sys.path.insert(0, <its own directory>)`, so the folders
travel with the scripts. No install step, no `PYTHONPATH`, no package manager.

---

## Module map

### `xemu_engine_lib/` — from `xemu_cheat_engine.py` (11,451 lines)

| Module | Lines | Contents |
|---|---:|---|
| `prelude` | 52 | Shared imports, numpy probe, Windows ctypes definitions |
| `engine_core` | 990 | `XemuTrainerEngine` — attach, RAM read/write, scanning, freeze loop |
| `regions` | 123 | Xbox region map, XBE section parsing, `describe_address` |
| `ui_widgets` | 493 | Wheel binding, menus, clipboard fix, geometry, monitors |
| `gdb_client` | 353 | `GdbClient`, `GdbStubError`, `disassemble_at` |
| `func_index` | 449 | `FunctionIndex` — symbol/RTTI/string cross-referencing |
| `sendtables` | 422 | `SendTableIndex` |
| `debug_session` | 941 | `DebugSession`, `Breakpoint`, condition compiler |
| `pagemap` | 597 | `XboxPageMap`, `PointerMap`, chain scanning + verification |
| `trainer_window` | 3,222 | `TrainerWindow` |
| `gdb_broker` | 554 | `GdbBroker`, `GdbWatchWindow` |
| `disasm_window` | 2,315 | `DisassemblyWindow` |
| `memviewer` | 970 | `TabbedMemoryViewer` |

### `xemu_trainer_lib/` — from `xemu_cheats_trainer.py` (3,683 lines)

| Module | Lines | Contents |
|---|---:|---|
| `prelude` | 42 | Shared imports, Windows ctypes definitions |
| `mem` | 166 | `XemuMemory` — attach and raw read/write |
| `ui_widgets` | 261 | Wheel binding, menus, clipboard fix |
| `pagemap` | 114 | `XboxPageMap` (on-demand walker) |
| `cheat_tree` | 66 | Node construction and traversal primitives |
| `gdb_lite` | 143 | `GdbLite` |
| `tree_ops` | 117 | Enable state, sorting, normalising, counting |
| `codes` | 830 | `CheatEngine` — all code types, ASM patch journal |
| `config` | 117 | `Config` |
| `app` | 1,836 | `CheatManagerApp` |

Dependency direction is one-way in both packages, and there are **no import
cycles**. `ui_*` depends on logic; logic never imports UI.

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

## What was NOT tested

**Neither GUI was actually launched.** The sandbox blocks the X socket, so a
virtual display would not connect. Everything above is static analysis, import
testing, and headless functional testing of the pure-logic surface.

First run is the real test. Worth exercising specifically:

- both windows building and showing their full widget tree
- attach to a running Xemu, then a first scan and a next scan
- the freeze thread applying a cheat continuously
- pointer wizard, disassembly window, memory viewer tabs
- a GDB connect and a breakpoint hit

If something misbehaves, the module names above narrow it immediately — that is
most of the point of the split.

---

## Deliberately unchanged

No behaviour was altered, no bugs fixed, no performance touched. In particular
these were left exactly as found:

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

The larger unification — one shared core behind both front-ends, removing the
three drifted parallel implementations of process attach, page translation, and
the GDB protocol — is described in the earlier plan document and is a separate
piece of work.
# Xemu-Cheat-Engine-And-Trainer-
