"""Reusable Tk helpers: mouse wheel binding, menus, clipboard, geometry.

Extracted verbatim from xemu_cheat_engine.py.
"""
from .prelude import *  # noqa: F401,F403
import os, sys, time, socket, struct, platform, threading, re, configparser, json
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk, filedialog
try:
    import numpy as np
    _HAVE_NUMPY = True
except ImportError:
    _HAVE_NUMPY = False


MIN_WINDOW = (480, 360)

def sane_geometry(widget, x, y, w, h, minimum=MIN_WINDOW):
    """
    Validate a saved window rectangle before restoring it.

    Two ways a saved geometry becomes a trap. A window can be saved at a
    degenerate size - 1x1 turned up in testing after a headless run - and
    restoring it gives a window with no visible content and no obvious way
    back. And a position saved on a second monitor puts the window somewhere
    unreachable once that monitor is unplugged, which is a real hazard on a
    multi-head desktop.

    So: clamp the size up to a usable minimum, and if the rectangle does not
    overlap any current display, move it onto the nearest one.
    """
    w = max(int(w), minimum[0])
    h = max(int(h), minimum[1])
    x, y = int(x), int(y)
    visible = False
    for mx, my, mw, mh in screen_monitors(widget):
        # An overlap of a few pixels is not enough to grab a title bar with.
        if (x + w > mx + 40 and x < mx + mw - 40
                and y + h > my and y < my + mh - 40):
            visible = True
            break
    if not visible:
        mx, my, mw, mh = monitor_at(widget, x, y)
        x = max(mx, min(x, mx + mw - w))
        y = max(my, min(y, my + mh - h))
    return f"{w}x{h}+{x}+{y}"

def bind_wheel(widget, on_scroll, add=None):
    """
    Wire the mouse wheel on every platform.

    X11 reports the wheel as Button-4 (up) and Button-5 (down); Windows and
    macOS send <MouseWheel> with a delta. on_scroll gets -1 for up, +1 for down.
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

def install_global_wheel(root):
    """
    Make the mouse wheel work over every scrollable widget, present and future.

    Done with CLASS bindings rather than by walking the widget tree, because
    half of these widgets do not exist yet when this runs - tabs, result rows
    and debugger panels are all created later - and a tree walk would silently
    miss them.

    Widget-level bindings still win: bind_wheel() returns "break", which stops
    Tk before it reaches the class binding, so anything with bespoke wheel
    behaviour (the results list, the interval spinner, the hex view) keeps it.
    """
    def wheel_dir(event):
        if getattr(event, 'num', None) == 4:
            return -1
        if getattr(event, 'num', None) == 5:
            return 1
        return -1 if getattr(event, 'delta', 0) > 0 else 1

    def scroller(units, horizontal=False):
        def handler(event):
            w = event.widget
            try:
                view = w.xview_scroll if horizontal else w.yview_scroll
            except AttributeError:
                return None
            try:
                view(wheel_dir(event) * units, "units")
            except tk.TclError:
                return None
            return "break"
        return handler

    def notebook_handler(event):
        """Wheel over the TAB STRIP cycles tabs; over the page it scrolls."""
        nb = event.widget
        try:
            # index("@x,y") names the tab under the pointer and raises when the
            # pointer is not over one, which is the reliable test. identify()
            # returns an element name that is only "label" over the tab TEXT,
            # so it misses the padding around it and the wheel appears dead on
            # part of the strip.
            nb.index(f"@{event.x},{event.y}")
            tabs = nb.tabs()
            if len(tabs) < 2:
                return "break"
            cur = nb.index("current")
            nxt = (cur + wheel_dir(event)) % len(tabs)
            nb.select(tabs[nxt])
        except tk.TclError:
            return None
        return "break"

    seqs = ("<MouseWheel>", "<Button-4>", "<Button-5>")
    shift = ("<Shift-MouseWheel>", "<Shift-Button-4>", "<Shift-Button-5>")
    # One row/line per notch for data lists - three is unusable when you are
    # reading a value off a row. Text and canvases keep the usual three.
    for cls, units in (("Treeview", 1), ("Listbox", 1), ("Text", 3),
                       ("Canvas", 3)):
        for seq in seqs:
            root.bind_class(cls, seq, scroller(units))
        for seq in shift:
            root.bind_class(cls, seq, scroller(units, horizontal=True))
    for seq in seqs:
        root.bind_class("TNotebook", seq, notebook_handler)

def bind_wheel_children(widget, on_scroll):
    """Same, applied to a container and every widget currently inside it."""
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

def _fit_menu_columns(menu, screen_h, recurse=True):
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
        if not recurse:
            return
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

def fit_cascade_submenus(menu, mon, post_x, post_y, depth=0):
    """
    Column-fit each submenu to the room below where Tk will actually post it.

    Fitting a submenu against the full monitor height is not enough. Tk posts a
    cascade level with its top at the parent ENTRY, so a 500px submenu opened
    from an entry 200px above the bottom of the display still sinks off it -
    which is exactly what was left over after the top-level menu was fixed.

    menu.yposition(i) gives the entry's offset inside its menu, and the caller
    already knows where the parent is going to be posted, so the available
    height is computable before anything is on screen. There is no API to move
    a cascade after Tk posts it, so this is the only chance.
    """
    if depth > 3:
        return
    _mx, my, mw, mh = mon
    try:
        end = menu.index("end")
        if end is None:
            return
        menu.update_idletasks()
        for i in range(end + 1):
            try:
                if menu.type(i) != "cascade":
                    continue
                name = menu.entrycget(i, "menu")
                if not name:
                    continue
                sub_menu = menu.nametowidget(name)
                try:
                    entry_y = post_y + menu.yposition(i)
                except tk.TclError:
                    entry_y = post_y
                avail = (my + mh) - entry_y
                # +60 undoes the margin _fit_menu_columns subtracts, so `avail`
                # means the same thing at both ends.
                _fit_menu_columns(sub_menu, max(160, avail + 60), recurse=False)
                sub_menu.update_idletasks()
                fit_cascade_submenus(sub_menu, mon,
                                     post_x + menu.winfo_reqwidth(), entry_y,
                                     depth + 1)
            except (tk.TclError, KeyError):
                continue
    except tk.TclError:
        pass

GDB_DEFAULT_HOST, GDB_DEFAULT_PORT = "127.0.0.1", 1234

_MONITORS = None

def screen_monitors(widget):
    """
    Physical display rectangles as [(x, y, w, h)].

    Tk only knows the whole X screen, which on a multi-monitor desktop is the
    bounding box of every display. A menu posted at y=1000 on a 1080-tall
    monitor therefore looks like it fits when the bounding box is 1440 tall,
    and it opens with its lower half off the bottom of that monitor. The fix
    needs real per-display geometry, which Tk does not expose, so it is queried
    from the platform once and cached.
    """
    global _MONITORS
    if _MONITORS is not None:
        return _MONITORS
    mons = []
    try:
        if sys.platform.startswith("win"):
            import ctypes
            from ctypes import wintypes

            class RECT(ctypes.Structure):
                _fields_ = [("left", wintypes.LONG), ("top", wintypes.LONG),
                            ("right", wintypes.LONG), ("bottom", wintypes.LONG)]

            class MONITORINFO(ctypes.Structure):
                _fields_ = [("cbSize", wintypes.DWORD), ("rcMonitor", RECT),
                            ("rcWork", RECT), ("dwFlags", wintypes.DWORD)]

            cb = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p,
                                    ctypes.c_void_p, ctypes.POINTER(RECT),
                                    ctypes.c_double)

            def _cb(hmon, hdc, lprc, data):
                mi = MONITORINFO()
                mi.cbSize = ctypes.sizeof(MONITORINFO)
                if ctypes.windll.user32.GetMonitorInfoW(hmon, ctypes.byref(mi)):
                    # rcWork excludes the taskbar, which is what a menu must
                    # avoid as much as it must avoid the screen edge.
                    r = mi.rcWork
                    mons.append((r.left, r.top, r.right - r.left,
                                 r.bottom - r.top))
                return 1

            ctypes.windll.user32.EnumDisplayMonitors(None, None, cb(_cb), 0)
        elif sys.platform != "darwin":
            # macOS Tk already places menus correctly; X11 does not.
            import re as _re
            import subprocess
            out = subprocess.run(["xrandr", "--listmonitors"],
                                 capture_output=True, text=True, timeout=2).stdout
            for m in _re.finditer(r"(\d+)/\d+x(\d+)/\d+\+(\d+)\+(\d+)", out):
                w, h, x, y = (int(g) for g in m.groups())
                mons.append((x, y, w, h))
    except Exception:
        mons = []
    if not mons:
        mons = [(0, 0, widget.winfo_screenwidth(), widget.winfo_screenheight())]
    _MONITORS = mons
    return mons

def monitor_at(widget, x, y):
    """The display rectangle containing a root coordinate, or the nearest."""
    mons = screen_monitors(widget)
    for mx, my, mw, mh in mons:
        if mx <= x < mx + mw and my <= y < my + mh:
            return mx, my, mw, mh
    best, bestd = mons[0], None
    for mx, my, mw, mh in mons:
        dx = max(mx - x, 0, x - (mx + mw - 1))
        dy = max(my - y, 0, y - (my + mh - 1))
        d = dx * dx + dy * dy
        if bestd is None or d < bestd:
            best, bestd = (mx, my, mw, mh), d
    return best

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
        # Bounds of the monitor the click happened on, NOT the whole X screen.
        mx, my, mw, mh = monitor_at(menu, x_root, y_root)
        # Make it fit first, then place it. Placement cannot rescue a menu
        # that is taller than the display to begin with.
        _fit_menu_columns(menu, mh)
        h, w = menu.winfo_reqheight(), menu.winfo_reqwidth()
        x, y = x_root, y_root
        if y + h > my + mh:
            y = y_root - h              # prefer flipping above the cursor
            if y < my:
                y = max(my, my + mh - h)   # taller than the display: clamp
        if x + w > mx + mw:
            x = max(mx, mx + mw - w)
        # Now that the final position is known, size the submenus to the room
        # that is actually left below each of their parent entries.
        fit_cascade_submenus(menu, (mx, my, mw, mh), x, y)
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

