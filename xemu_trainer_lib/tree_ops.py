"""Tree queries: enable state, sorting, normalising, counting.

Extracted verbatim from xemu_cheats_trainer.py.
"""
from .prelude import *  # noqa: F401,F403
import os, sys, time, struct, platform, threading, re, json, configparser
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from .cheat_tree import is_group, new_bid, walk_cheats  # noqa: F401


def enabled_cheats(nodes):
    return [c for c in walk_cheats(nodes) if c.get('enabled')]

def group_state(node):
    """'on', 'off', 'partial', or 'empty' for a group node."""
    cheats = list(walk_cheats(node['children']))
    if not cheats:
        return 'empty'
    on = sum(1 for c in cheats if c.get('enabled'))
    if on == 0:
        return 'off'
    if on == len(cheats):
        return 'on'
    return 'partial'

def set_subtree_enabled(node, value):
    """Enable or disable every cheat at or below `node`. Returns changed cheats."""
    changed = []
    targets = walk_cheats(node['children']) if is_group(node) else [node]
    for c in targets:
        if c.get('enabled') != value:
            c['enabled'] = value
            changed.append(c)
    return changed

def sort_key(node):
    """Groups before cheats, then case-insensitive by name."""
    return (0 if is_group(node) else 1, node['name'].lower())

def sort_tree(nodes):
    """
    Sort a level alphabetically in place, and recurse.

    Only used by the explicit "Sort permanently" action. Ordinary display
    sorting does NOT mutate the list, because the stored order IS the
    insertion order - destroying it would make "Order added" unrecoverable.
    """
    nodes.sort(key=sort_key)
    for node in nodes:
        if is_group(node):
            sort_tree(node['children'])

def group_paths(nodes, prefix=""):
    """[(display path, children list)] for every group in the tree."""
    out = []
    for node in nodes:
        if is_group(node):
            path = f"{prefix} / {node['name']}" if prefix else node['name']
            out.append((path, node['children']))
            out.extend(group_paths(node['children'], path))
    return out

def normalise_tree(nodes):
    """Repair a tree loaded from disk: assign ids, fill in defaults, drop junk."""
    out = []
    for node in nodes:
        if not isinstance(node, dict) or 'name' not in node:
            continue
        node['_bid'] = new_bid()
        if is_group(node):
            if not isinstance(node['children'], list):
                node['children'] = []
            node['expanded'] = bool(node.get('expanded', True))
            node['children'] = normalise_tree(node['children'])
        else:
            codes = node.get('codes') or []
            # JSON round-trips tuples as lists; the engine indexes them either
            # way, but keep them as tuples so identity checks stay cheap.
            node['codes'] = [tuple(c) for c in codes if len(c) == 2]
            if not node['codes']:
                continue
            node['enabled'] = bool(node.get('enabled', False))
            node['desc'] = str(node.get('desc', "") or "")
            node['author'] = str(node.get('author', "") or "")
        out.append(node)
    return out

def strip_tree(nodes):
    """Serialisable copy - drops runtime-only keys (_bid, _var, _timer_id)."""
    out = []
    for node in nodes:
        if is_group(node):
            out.append({'name': node['name'],
                        'expanded': bool(node.get('expanded', True)),
                        'children': strip_tree(node['children'])})
        else:
            out.append({'name': node['name'],
                        'codes': [list(c) for c in node['codes']],
                        'enabled': bool(node.get('enabled', False)),
                        'desc': node.get('desc', ""),
                        'author': node.get('author', "")})
    return out

def count_tree(nodes):
    """(groups, cheats) below this level."""
    g = c = 0
    for node in nodes:
        if is_group(node):
            g += 1
            sg, sc = count_tree(node['children'])
            g += sg
            c += sc
        else:
            c += 1
    return g, c

