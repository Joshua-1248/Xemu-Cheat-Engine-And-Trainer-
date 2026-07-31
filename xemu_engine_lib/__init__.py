"""Xemu Cheat Engine — implementation package.

Module map (each file holds code moved verbatim from the
original xemu_cheat_engine.py):

    prelude          shared imports / platform defs
    engine_core      Core engine: process attach, RAM read/write, value scanning, freeze loop.
    regions          Xbox memory region map, XBE parsing, address description.
    ui_widgets       Reusable Tk helpers: mouse wheel binding, menus, clipboard, geometry.
    gdb_client       GDB remote-serial-protocol client for the Xemu stub.
    func_index       Function discovery, symbol loading, RTTI/string cross-referencing.
    sendtables       SendTable layout inference and class/field lookup.
    debug_session    Breakpoints, conditions, and the stateful debug session.
    pagemap          Guest page-table translation and pointer-chain scanning.
    trainer_window   Main trainer window (scan UI, cheat table, pointer wizard).
    gdb_broker       Shared GDB connection broker and the watchpoint window.
    disasm_window    Disassembly view with integrated debugger panels.
    memviewer        Tabbed hex memory viewer.
"""
