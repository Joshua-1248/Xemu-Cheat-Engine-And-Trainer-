"""Cheat/group node construction and tree traversal primitives.

Extracted verbatim from xemu_cheats_trainer.py.
"""
from .prelude import *  # noqa: F401,F403
import os, sys, time, struct, platform, threading, re, json, configparser
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog


_next_bid = [0]

def new_bid():
    _next_bid[0] += 1
    return _next_bid[0]

def is_group(node):
    return 'children' in node

def make_cheat(name, codes, enabled=False, desc="", author=""):
    return {'name': name, 'codes': codes, 'enabled': enabled,
            'desc': desc, 'author': author, '_bid': new_bid()}

def make_group(name, children=None, expanded=True):
    return {'name': name, 'children': children if children is not None else [],
            'expanded': expanded, '_bid': new_bid()}

def group_child(children, name):
    """Return the child list of the group called `name`, creating it if absent."""
    for node in children:
        if is_group(node) and node['name'].lower() == name.lower():
            return node['children']
    grp = make_group(name)
    children.append(grp)
    return grp['children']

def walk_cheats(nodes):
    """Yield every cheat node in the tree, depth first."""
    for node in nodes:
        if is_group(node):
            yield from walk_cheats(node['children'])
        else:
            yield node

def walk_nodes(nodes, parent=None):
    """Yield (node, parent_list) for every node in the tree, depth first."""
    for node in nodes:
        yield node, nodes if parent is None else parent
        if is_group(node):
            yield from walk_nodes(node['children'], node['children'])

SECTIONS = ("cheats", "patches")

def game_section(game, section):
    """The named node list for a game, created on demand."""
    if section not in SECTIONS:
        section = "cheats"
    return game.setdefault(section, [])

def all_game_nodes(game):
    """
    Every cheat block in the game, from both sections.

    Blocks in the patches section are tagged `_asm` on the way out. A patch is
    by definition an edit to code, and a code edit written straight to RAM has
    no effect under QEMU's JIT - it keeps running the block it already
    translated. The tag routes the write through the gdbstub instead, and makes
    the block journal its original bytes so disabling it can put them back.

    Tagged here rather than at load time because this is the one call both the
    freeze loop and the restore pass go through, so the two cannot disagree
    about which blocks are patches. The key is in-memory only - the on-disk
    format writes a fixed set of fields and ignores it.
    """
    out = []
    for section in SECTIONS:
        # list() is load-bearing: walk_cheats is a generator, so tagging by
        # iterating it would leave it exhausted and extend() would add nothing.
        nodes = list(walk_cheats(game.get(section, []) or []))
        is_patch = (section == 'patches')
        for n in nodes:
            # Assigned either way: a block dragged from patches to cheats must
            # lose the tag, not keep a stale True.
            n['_asm'] = is_patch
        out.extend(nodes)
    return out

