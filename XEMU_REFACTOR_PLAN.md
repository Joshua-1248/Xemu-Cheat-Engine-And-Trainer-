# Xemu Toolchain — Restructuring Plan

Status: analysis complete, no code changed yet.
Baseline commit: *(record hash here before starting)*

---

## 1. What we're actually dealing with

| File | Lines | Bytes |
|---|---:|---:|
| `xemu_cheat_engine.py` | 11,451 | 514 KB |
| `xemu_cheats_trainer.py` | 3,683 | 154 KB |
| **Total** | **15,134** | **668 KB** |

Considerably larger than the ~1,700-line figure from earlier sessions. The
cheat engine has since grown a GDB stub client, a full debug session layer, a
disassembler window, an RTTI/function indexer, and a tabbed memory viewer.

### Code health baseline

Ran `pyflakes` + an AST pass for shadowed methods across both files:

- No undefined names.
- No duplicate method definitions (no silently-shadowed overrides).
- One unused local: `xemu_cheat_engine.py:8516` — `vt` assigned, never read.

This is a well-maintained codebase. The restructure is about **structure and
duplication**, not about repairing rot.

---

## 2. Key finding: the GUI/logic split is already mostly clean

Classified every top-level class and function by whether it touches Tk:

| File | GUI-independent | GUI code | % pure |
|---|---:|---:|---:|
| `xemu_cheat_engine.py` | 4,101 ln | 7,015 ln | 37% |
| `xemu_cheats_trainer.py` | 1,614 ln | 1,895 ln | 46% |

**The two most important classes are already 100% Tk-free:**

- `XemuTrainerEngine` (947 ln, engine) — zero Tk references
- `CheatEngine` (815 ln, trainer) — zero Tk references

These lift out mechanically. No decoupling surgery required. That is the single
best piece of news in this analysis — the expensive part of a GUI/logic split
has effectively already been done by hand.

Also fully Tk-free and liftable:

| Item | File | Lines |
|---|---|---:|
| `DebugSession` | engine | 756 |
| `FunctionIndex` | engine | 433 |
| `SendTableIndex` | engine | 406 |
| `GdbClient` | engine | 315 |
| `XboxPageMap` | engine | 221 |
| `XemuMemory` | trainer | 155 |
| `GdbLite` | trainer | 128 |
| `PointerMap` | engine | 113 |
| `Config` | trainer | 105 |
| `scan_chains` + verified variants | engine | ~200 |
| cheat-tree helpers (`walk_cheats`, `group_state`, …) | trainer | ~120 |

---

## 3. Key finding: the duplication is *conceptual*, not textual

Verbatim copy-paste is modest:

- **245 lines** duplicated byte-for-byte (`install_clipboard_fix` at 122 ln is
  the bulk; plus `entry_copy`/`entry_paste`/`text_copy`/`text_paste`,
  `bind_wheel_cycle`, `bind_wheel_number`, `MEMORY_BASIC_INFORMATION`)
- **101 lines** near-duplicated ≥80% (`_fit_menu_columns` 98.5%, `bind_wheel`,
  `PROCESSENTRY32`)

The real problem is **three pairs of parallel implementations of the same
concept that have drifted apart**:

| Concept | Engine | Trainer | Similarity |
|---|---|---|---:|
| Process attach + RAM read/write | `XemuTrainerEngine` (947 ln) | `XemuMemory` (155 ln) | `read_mem` 26%, `write_mem` 15% |
| Guest page-table translation | `XboxPageMap` (221 ln) | `XboxPageMap` (103 ln) | 11.5% |
| GDB stub protocol | `GdbClient` (315 ln) | `GdbLite` (128 ln) | `_cmd` 69%, `_read_packet` 12% |

This is worse than copy-paste. Copy-paste at least stays in sync when you
remember to update both. Drifted parallel implementations **disagree**, and a
fix applied to one never reaches the other.

### Confirmed instance of that drift

`XboxPageMap.__init__` is the pure-Python original in the trainer and the
numpy-vectorized version in the engine. Benchmarked both against a synthetic
64 MB Xbox RAM image with a realistic page directory:

```
trainer (pure Python):  10854.5 ms
engine  (numpy)      :     28.0 ms
speedup              :    387.0x
results identical    : True (0 mismatches)
```

Same output, 387× apart. This is the identical failure mode fixed in
`execute_next_scan_logic` in an earlier session — per-element Python loops over
a million entries — still living in the trainer.

**Mitigating detail:** the trainer never actually constructs `XboxPageMap(dump)`.
It only calls `XboxPageMap.on_demand(...)`, the lazy walker. So the 11-second
build is currently **dead code**. It is not costing runtime today — but it is a
landmine for anyone who later wires up a full-dump path in the trainer (the
engine has four such call sites). Delete it or replace it with the engine's
version; do not leave it sitting there.

### Divergence requiring a decision, not obviously a bug

The engine's `XboxPageMap._walk` clears its translation cache on a `CACHE_TTL`
timer and caps at 8192 entries. The trainer's `_walk` has no TTL and caps at
4096; instead the trainer detects staleness one level up, in
`CheatEngine._pagemap_is_stale`, by re-reading a single probe PDE covering the
XBE image.

Both approaches are defensible and the trainer's comment documents real
measurements behind it (stale maps landing writes 128 KB off target in 5 of 6
cross-level cases). **Pick one deliberately when unifying** — do not let the
merge silently choose. The trainer's probe approach looks better-founded; the
engine's TTL is cheaper but time-based rather than evidence-based.

---

## 4. Oversized units (secondary, address after the split)

| Method | File | Lines |
|---|---|---:|
| `TabbedMemoryViewer.add_tab` | engine | 709 |
| `TrainerWindow._build_gui` | engine | 519 |
| `TrainerWindow.update_table_view` | engine | 390 |
| `TrainerWindow.pointer_wizard` | engine | 367 |
| `CheatManagerApp._build_gui` | trainer | 267 |
| `TrainerWindow.add_pointer_entry` | engine | 207 |
| `DebugSession` (class) | engine | 756 |
| `TrainerWindow` (class) | engine | 3,200 |
| `DisassemblyWindow` (class) | engine | 2,293 |
| `CheatManagerApp` (class) | trainer | 1,819 |

A 709-line method is a module wearing a `def`. These are worth breaking up, but
**only after** the package structure exists — splitting them first just moves
the problem around.

---

## 5. Target layout

One shared core, two thin front-ends. This is the recommendation: the overlap is
in exactly the subsystems that are hardest to get right (page-table walking,
GDB protocol, process attach), and those are the ones currently forked.

```
xemu_tools/
├── core/
│   ├── __init__.py
│   ├── process.py        ← unified attach + read_mem/write_mem
│   │                       (from XemuTrainerEngine + XemuMemory)
│   ├── pagemap.py        ← ONE XboxPageMap (engine's numpy version +
│   │                       trainer's probe-based staleness detection)
│   ├── regions.py        ← XBOX_REGIONS, detect_xbe_region,
│   │                       parse_xbe_sections, describe_address
│   ├── scan.py           ← execute_first_scan_logic, execute_next_scan_logic,
│   │                       _filter_offsets, type params (pure, numpy)
│   ├── pointers.py       ← PointerMap, scan_chains, scan_chains_verified,
│   │                       verify_chains, resolve_with_index
│   └── codes.py          ← CheatEngine code interpreter (type3/4/5/6/7/89A/B/D)
├── gdb/
│   ├── __init__.py
│   ├── client.py         ← ONE GdbClient (GdbLite becomes a thin facade
│   │                       or is deleted outright)
│   ├── session.py        ← DebugSession, Breakpoint, parse_stop_reply,
│   │                       compile_condition
│   └── broker.py         ← GdbBroker
├── analysis/
│   ├── __init__.py
│   ├── functions.py      ← FunctionIndex
│   ├── sendtables.py     ← SendTableIndex
│   └── disasm.py         ← disassemble_at + capstone glue
├── ui/
│   ├── __init__.py
│   ├── widgets.py        ← bind_wheel*, popup_menu, _fit_menu_columns,
│   │                       install_clipboard_fix, sane_geometry,
│   │                       screen_monitors  ← kills all 346 duplicated lines
│   ├── theme.py          ← colors, fonts, hover styling
│   ├── trainer_window.py ← TrainerWindow
│   ├── disasm_window.py  ← DisassemblyWindow
│   ├── memviewer.py      ← TabbedMemoryViewer
│   ├── gdb_watch.py      ← GdbWatchWindow
│   └── cheat_manager.py  ← CheatManagerApp
├── config.py             ← Config (trainer) + engine settings persistence
├── cheat_engine_main.py  ← entry point 1
└── trainer_main.py       ← entry point 2
```

**Dependency rule, enforced strictly:** `ui/` imports `core/`, `gdb/`,
`analysis/`. None of those ever import `ui/`. Progress and events flow upward
via callbacks passed in by the UI, never by touching a widget from logic. This
is what prevents the circular-import spiral that Tkinter projects fall into.

---

## 6. Extraction order

Leaf-first. **Run both tools after every single step.** A step that breaks
something is trivially attributable; a big-bang restructure is not.

| Step | Extract | Risk | Why this order |
|---:|---|---|---|
| 0 | `git init`, commit, tag `pre-refactor` | — | Escape hatch |
| 0b | Capture RAM dump + known-good scan results | — | Regression oracle |
| 1 | `ui/widgets.py` | Very low | Pure leaf; removes 346 dup lines immediately, both files import it |
| 2 | `core/regions.py` | Very low | Constants + 3 small pure functions |
| 3 | `core/pagemap.py` | **Medium** | The unification decision (§3) lands here |
| 4 | `core/process.py` | Medium | Two implementations to reconcile |
| 5 | `core/scan.py` | Low | Already pure numpy, lifts cleanly |
| 6 | `core/pointers.py` | Low | Depends only on pagemap + process |
| 7 | `core/codes.py` | Low | `CheatEngine` is already Tk-free |
| 8 | `gdb/client.py` | Medium | Reconcile `GdbClient` / `GdbLite` |
| 9 | `gdb/session.py`, `gdb/broker.py` | Low | Depend on client only |
| 10 | `analysis/*` | Low | Already Tk-free |
| 11 | `ui/*` windows | Low | Whatever is left; mostly a move |
| 12 | Entry points + `zipapp` packaging | Low | Restore single-file distribution |

Steps 3, 4 and 8 are the only ones requiring judgement calls. Everything else is
mechanical movement.

---

## 7. Rules for the restructure phase

1. **Behavior-preserving only.** Code moves byte-identical apart from imports.
   No performance changes, no bug fixes, no cleanup. Optimization happens
   *after*, inside the new boundaries, where each change is isolated.
2. **Exception:** the three unification decisions (§6 steps 3, 4, 8) inherently
   change behavior for one of the two tools. Do them one at a time, deliberately,
   with the reasoning recorded here.
3. **`vt` at `xemu_cheat_engine.py:8516`** — leave it. Fix it in the cleanup
   pass so it doesn't muddy a "pure move" diff.
4. **Preservation constraint carried forward:** no modification of original
   game data at any point in the pipeline.

---

## 8. What this buys, concretely

- **Headless regression tests.** With `core/scan.py` and `core/pointers.py`
  Tk-free and importable, the RAM dump from step 0b drives assertions in
  milliseconds. The item-size bug and the pointer-finder normalization bug from
  earlier sessions both become one-second test failures instead of
  discovered-weeks-later surprises.
- **Multiprocessing becomes possible.** Worker functions must be importable at
  module level to be picklable. A first scan over a 128 MB address space can
  then be split across cores.
- **One page-table walker.** Currently a fix has to be applied twice, correctly,
  from memory, in two files that already disagree.
- **Reuse against other targets.** A scanner taking `(buffer, comparison_op)`
  doesn't care that the buffer came from Xemu — the same module works against
  Project64 RDRAM or a PCSX save state.
- **Reviewable diffs.** Every commit currently touches one of two enormous
  files. Afterward, `git log` names the subsystem, and `git bisect` lands
  somewhere meaningful.
