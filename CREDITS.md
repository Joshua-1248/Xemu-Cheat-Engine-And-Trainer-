# Credits and third-party notices

This project is licensed under the MIT License (see `LICENSE`). All code in
`xemu_engine_lib/` and `xemu_trainer_lib/` is an original implementation.

## Reference material

The cheat code type system (types 0-F, dispatched on the top nibble of the
first word) follows the raw code format of the Action Replay / GameShark /
CodeBreaker lineage. The following projects were consulted as documentation of
those semantics. No source code was copied from any of them.

- **PS2rd** — Mathias Lafeldt (misfire). https://github.com/mlafeldt/ps2rd
  Consulted for raw code type semantics. PS2rd's engine is MIPS assembly for
  the PlayStation 2; this project's interpreter is an independent Python
  implementation targeting the Original Xbox, including code types (8/9/A
  virtual writes, type 6 address-space flag, type E switch) that have no
  counterpart there.

- **Gecko codes** (Nintendo Wii / GameCube) — code type E, the conditional
  ON/OFF switch, is modelled on the Gecko `CC` (button-activator) code concept.
  Gecko's design is what makes a held condition behave as a toggle: the switch
  flips on a false-to-true edge and the guarded lines keep running while it is
  on. The field layout is this project's own, reusing type D's exactly so that
  a D code becomes a switch by changing one nibble.

- **PCSX2** — three interface conventions are followed so the tools feel
  familiar: the per-game cheat file naming stem (pnach style), the breakpoint
  condition syntax (`&&`, `||`, `[esp+4]`, `u8[...]`), and the debugger
  keyboard shortcuts. The condition compiler itself is an original
  implementation that rewrites the expression and compiles it against a
  whitelisted Python AST node set.

- **Cheat Engine** — user-interface conventions only: manual pointer-chain
  entry, scan comparison semantics, and address-table layout. No code is shared.
  This project is not affiliated with or derived from Cheat Engine.

- **Xbox hardware and XBE format** — the memory region map (kernel window, page
  table self-map, NV2A and APU register ranges) and the XBE header/section
  layout are publicly documented hardware and file-format facts, drawn from the
  Original Xbox homebrew community's reference material.

## RTTI / vtable recovery

`disasm_window._scan_rtti` and `_rtti_name` walk the Microsoft Visual C++ RTTI
structures to recover `Class::vtable[n]` names. The structure layout used —
`RTTICompleteObjectLocator` at vtable[-1], its `pTypeDescriptor` field at
offset 0x0C, the `TypeDescriptor` name string at offset 8, and validation via
the `.?AV` mangled-name prefix — is long-published public documentation of the
MSVC ABI. See, for example:

- Sabanal & Yason, "Reversing C++" (Black Hat DC 2007)
- Quarkslab, "Visual C++ RTTI Inspection" (2013)

No code was copied from any RTTI scanner. The traversal is dictated by the
structure layout itself; the surrounding implementation — locating the image by
`XBEH` magic, the XBE header and section-table parsing, guest page-table
address translation, and the .rdata scan heuristics — is specific to the
Original Xbox and original to this project.

`sendtables.SendTableIndex` recovers Source engine networked field names by
inferring the SendTable struct layout empirically from the target image. It
does not use, include, or derive from the Source SDK.

## Runtime dependencies

Not redistributed; installed separately via pip.

- **NumPy** — BSD 3-Clause. Used for vectorised memory scanning.
- **Capstone** — BSD 3-Clause. Imported lazily for x86 disassembly; the tools
  degrade gracefully when it is absent.

Neither is bundled, vendored, or modified.

## Interoperability

This project communicates with **xemu** (https://xemu.app, GPLv2) as a separate
process over the GDB Remote Serial Protocol, a publicly documented wire
protocol. No xemu source is included, linked, or derived from.

## Cheat tables

The per-game files under `Tables/` and `cheats/` are the author's own reverse
engineering results, produced with these tools. They are not derived from any
existing cheat database.

## Disclaimer

Not affiliated with, endorsed by, or sponsored by Microsoft, or by any of the
projects named above. All trademarks are the property of their respective
owners.
