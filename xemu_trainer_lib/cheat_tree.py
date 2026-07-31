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
    """Every cheat block in the game, from both sections."""
    out = []
    for section in SECTIONS:
        out.extend(walk_cheats(game.get(section, []) or []))
    return out

