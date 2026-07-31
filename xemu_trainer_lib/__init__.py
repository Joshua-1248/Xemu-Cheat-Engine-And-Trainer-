"""Xemu Cheats Trainer — implementation package.

Module map (each file holds code moved verbatim from the
original xemu_cheats_trainer.py):

    prelude          shared imports / platform defs
    mem              Xemu process attach and raw RAM read/write.
    ui_widgets       Reusable Tk helpers: mouse wheel binding, menus, clipboard.
    pagemap          Guest page-table translation (on-demand walker).
    cheat_tree       Cheat/group node construction and tree traversal primitives.
    gdb_lite         Minimal GDB stub client used for ASM patches.
    tree_ops         Tree queries: enable state, sorting, normalising, counting.
    codes            Cheat code interpreter (all code types) and ASM patch journal.
    config           Settings persistence.
    app              Main cheat manager window.
"""
