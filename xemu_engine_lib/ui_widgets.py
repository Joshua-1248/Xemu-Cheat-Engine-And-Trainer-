"""Reusable Tk helpers: mouse wheel binding, menus, clipboard.

Extracted verbatim from xemu_cheats_trainer.py.
"""
from .prelude import *  # noqa: F401,F403
import os, sys, time, struct, platform, threading, re, json, configparser
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog


def bind_wheel(widget, on_scroll, add=None):
    """
    Wire the mouse wheel on every platform.

    X11 reports the wheel as Button-4 (up) and Button-5 (down); Windows and
    macOS send <MouseWheel> with a delta. Widgets that scroll natively on
    Windows - Treeview, Text, Listbox - do nothing on Linux without this, which
    is why the wheel only worked when the pointer was over the scrollbar.

    on_scroll is called with -1 for up and +1 for down.
    """
    def handler(event):
        if getattr(event, 'num', None) == 4:
            direction = -1
        elif getattr(event, 'num', None) == 5:
            direction = 1
        else:
            direction = -1 if getattr(event, 'delta', 0) > 0 else 1
        on_scroll(direction)
        return "break"
    for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
        widget.bind(seq, handler, add=add)
    return handler

def bind_wheel_children(widget, on_scroll):
    """Same, applied to a container and everything currently inside it."""
    bind_wheel(widget, on_scroll)
    for child in widget.winfo_children():
        bind_wheel_children(child, on_scroll)

def bind_wheel_cycle(widget, values, get_current, set_value):
    """Wheel over a control steps through `values` instead of scrolling."""
    def step(direction):
        vals = values() if callable(values) else values
        if not vals:
            return
        try:
            i = vals.index(get_current())
        except ValueError:
            i = 0
        set_value(vals[max(0, min(len(vals) - 1, i + direction))])
    return bind_wheel(widget, step)

def bind_wheel_number(widget, var, lo, hi, step=1, hexmode=False):
    """Wheel over a numeric entry nudges its value, clamped to [lo, hi]."""
    def bump(direction):
        raw = str(var.get()).strip()
        try:
            cur = int(raw, 16) if hexmode else int(raw, 0)
        except Exception:
            cur = lo
        new = max(lo, min(hi, cur - direction * step))
        var.set(f"{new:X}" if hexmode else new)
    return bind_wheel(widget, bump)

def _fit_menu_columns(menu, screen_h):
    """
    Break a menu into columns when it is taller than the screen.

    Repositioning only helps a menu that FITS. One that is simply too tall -
    "Move to group" with 60 groups, or a long address table menu - overhangs
    from wherever it is posted, and Tk on X11 gives no way to scroll it. Column
    breaks lay the surplus entries out sideways instead, which is how long
    menus have always been handled on X11.

    Recurses into cascades: a submenu is posted by Tk itself, so popup_menu
    never sees it and this is the only chance to make it fit.
    """
    try:
        end = menu.index("end")
        if end is None:
            return
        count = end + 1
        menu.update_idletasks()
        h = menu.winfo_reqheight()
        usable = max(120, screen_h - 60)
        if h > usable and count > 1:
            per = max(1, int(count * usable / h))
            for i in range(count):
                try:
                    menu.entryconfigure(i, columnbreak=1 if (i and i % per == 0)
                                        else 0)
                except tk.TclError:
                    pass        # tearoff and some separators refuse it
            menu.update_idletasks()
        for i in range(count):
            try:
                if menu.type(i) != "cascade":
                    continue
                name = menu.entrycget(i, "menu")
                if name:
                    _fit_menu_columns(menu.nametowidget(name), screen_h)
            except (tk.TclError, KeyError):
                pass
    except tk.TclError:
        pass

def popup_menu(menu, x_root, y_root):
    """
    Post a context menu, keeping it on screen.

    Tk repositions an oversized menu on Windows and macOS but NOT on X11, so a
    right-click near the bottom of the display posts a menu that runs off the
    edge with its lower entries unreachable. Flip it above the cursor when it
    would overhang, clamp if it is taller than the screen either way, and do
    the same horizontally.

    winfo_reqheight() is the menu's requested size, which is valid before the
    menu is mapped - winfo_height() would still report 1 here.
    """
    try:
        menu.update_idletasks()
        sh, sw = menu.winfo_screenheight(), menu.winfo_screenwidth()
        # Make it fit first, then place it. Placement cannot rescue a menu
        # that is taller than the screen to begin with.
        _fit_menu_columns(menu, sh)
        h, w = menu.winfo_reqheight(), menu.winfo_reqwidth()
        x, y = x_root, y_root
        if y + h > sh:
            y = y_root - h              # prefer flipping above the cursor
            if y < 0:
                y = max(0, sh - h)      # taller than the screen: clamp
        if x + w > sw:
            x = max(0, sw - w)
    except Exception:
        x, y = x_root, y_root
    menu.tk_popup(x, y)

def install_clipboard_fix(root):
    """
    Make Ctrl+C / Ctrl+X / Ctrl+V happen exactly once per keypress.

    Tk delivers a paste through the <<Paste>> virtual event, which every Entry
    and Text already handles via its CLASS binding. Anything the application
    adds on top - a bind_all("<Control-v>"), or a per-toplevel binding - runs
    IN ADDITION to that class binding, so the text lands twice. Returning
    "break" from the extra handler does not help, because widget and class
    bindings have already fired by the time the toplevel and "all" bindtags are
    reached.

    So the fix is to REPLACE the class bindings rather than layer onto them.
    bind_class() overwrites, and each handler returns "break", which stops the
    toplevel and "all" tags from contributing a second insert. On top of that,
    a guard drops any event whose X serial and target widget match the one just
    handled, which catches the same physical event being delivered twice.
    Serials are per-event and strictly increasing, so two real keypresses never
    collide - an earlier version of this guard used a 30 ms time window instead
    and swallowed legitimate back-to-back pastes.

    These handlers also replace the selection, which Tk's own X11 binding does
    not do - on Linux the stock behaviour is to insert alongside selected text
    rather than over it.
    """
    last = {'key': None, 'time': 0.0}

    def duplicate(event):
        serial = getattr(event, 'serial', None)
        key = (serial, str(getattr(event, 'widget', '')))
        now = time.monotonic()
        # The time check only expires stale state; it never suppresses on its
        # own, because a distinct event carries a distinct serial.
        if serial is not None and key == last['key'] and now - last['time'] < 0.25:
            return True
        last['key'] = key
        last['time'] = now
        return False

    def clip_get(widget):
        try:
            return widget.clipboard_get()
        except Exception:
            return None

    def entry_paste(event):
        w = event.widget
        if duplicate(event):
            return "break"
        text = clip_get(w)
        if text is None:
            return "break"
        text = text.strip()
        try:
            if w.selection_present():
                w.delete("sel.first", "sel.last")
        except Exception:
            pass
        try:
            w.insert("insert", text)
            w.icursor(w.index("insert"))
            w.see("insert")
        except Exception:
            pass
        return "break"

    def text_paste(event):
        w = event.widget
        if duplicate(event):
            return "break"
        text = clip_get(w)
        if text is None:
            return "break"
        try:
            if w.tag_ranges("sel"):
                w.delete("sel.first", "sel.last")
        except Exception:
            pass
        try:
            w.insert("insert", text)
            w.see("insert")
        except Exception:
            pass
        return "break"

    def entry_copy(event, cut=False):
        w = event.widget
        try:
            if not w.selection_present():
                return "break"
            text = w.get()[w.index("sel.first"):w.index("sel.last")]
        except Exception:
            return "break"
        w.clipboard_clear()
        w.clipboard_append(text)
        if cut:
            try: w.delete("sel.first", "sel.last")
            except Exception: pass
        return "break"

    def text_copy(event, cut=False):
        w = event.widget
        try:
            if not w.tag_ranges("sel"):
                return "break"
            text = w.get("sel.first", "sel.last")
        except Exception:
            return "break"
        w.clipboard_clear()
        w.clipboard_append(text)
        if cut:
            try: w.delete("sel.first", "sel.last")
            except Exception: pass
        return "break"

    for cls in ("Entry", "TEntry"):
        root.bind_class(cls, "<<Paste>>", entry_paste)
        root.bind_class(cls, "<<Copy>>", entry_copy)
        root.bind_class(cls, "<<Cut>>", lambda e: entry_copy(e, cut=True))
    root.bind_class("Text", "<<Paste>>", text_paste)
    root.bind_class("Text", "<<Copy>>", text_copy)
    root.bind_class("Text", "<<Cut>>", lambda e: text_copy(e, cut=True))

