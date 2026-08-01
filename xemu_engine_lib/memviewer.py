"""Tabbed hex memory viewer.

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
from .regions import XBOX_REGIONS  # noqa: F401
from .ui_widgets import bind_wheel, bind_wheel_cycle, popup_menu  # noqa: F401


class TabbedMemoryViewer:
    """
    A separate window displaying a hex dump of Xbox RAM.
    Supports multiple tabs, live updates, byte editing, and follow‑pointer.
    """

    def __init__(self, trainer_window, engine):
        self.tw = trainer_window
        self.engine = engine
        self.tabs = []          # list of dicts with id, state, frame
        self.next_tab_id = 1

        # If already open, just raise it
        if hasattr(trainer_window, 'active_mem_viewer') and \
           trainer_window.active_mem_viewer is not None:
            try:
                trainer_window.active_mem_viewer.winfo_exists()
                trainer_window.active_mem_viewer.lift()
                trainer_window.active_mem_viewer.focus_force()
                return
            except: pass

        self.win = tk.Toplevel(trainer_window)
        trainer_window.active_mem_viewer = self.win
        self.win.title("Hex Memory Viewer")
        self.win.geometry("730x460")
        self.win.update_idletasks()
        w = self.win.winfo_reqwidth()
        h = self.win.winfo_reqheight()
        x = (self.win.winfo_screenwidth() // 2) - (w // 2)
        y = (self.win.winfo_screenheight() // 2) - (h // 2)
        self.win.geometry(f"+{x}+{y}")
        self.win.configure(bg="#212121")

        # Restore saved geometry if available
        try:
            config = getattr(trainer_window, '_config', None)
            if config and 'memory_viewer' in config:
                mw = config.get('memory_viewer', 'width', fallback=None)
                mh = config.get('memory_viewer', 'height', fallback=None)
                mx = config.get('memory_viewer', 'x', fallback=None)
                my = config.get('memory_viewer', 'y', fallback=None)
                if all(v is not None for v in (mw, mh, mx, my)):
                    self.win.geometry(f"{mw}x{mh}+{mx}+{my}")
        except: pass

        # Top bar with "+" button to add new tabs
        bar = tk.Frame(self.win, bg="#212121")
        bar.pack(fill="x", padx=5, pady=(5,0))
        tk.Button(bar, text="+", font=("Helvetica",12,"bold"), bg="#424242",
                  fg="#FFFFFF", relief="flat", padx=8, pady=2,
                  command=lambda: self.add_tab(0)).pack(side="left")

        self.notebook = ttk.Notebook(self.win)

        def _wheel_tabs(direction):
            tabs = self.notebook.tabs()
            if len(tabs) < 2:
                return
            try:
                i = tabs.index(self.notebook.select())
            except ValueError:
                return
            self.notebook.select(tabs[(i + direction) % len(tabs)])
        bind_wheel(self.notebook, _wheel_tabs)
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)

        # Right‑click on a tab → close it
        def on_tab_right_click(event):
            try:
                tab_index = self.notebook.tk.call(self.notebook._w,
                                                  "identify", "tab",
                                                  event.x, event.y)
                if tab_index != "":
                    tab_index = int(tab_index)
                    if 0 <= tab_index < len(self.tabs):
                        tid = self.tabs[tab_index]['id']
                        menu = tk.Menu(self.win, tearoff=0)
                        menu.add_command(label="Close Tab",
                                         command=lambda: self._close_tab(tid))
                        popup_menu(menu, event.x_root, event.y_root)
            except: pass
        self.notebook.bind("<Button-3>", on_tab_right_click)

        def on_close():
            if hasattr(trainer_window, 'active_mem_viewer'):
                trainer_window.active_mem_viewer = None
            if hasattr(trainer_window, 'tabbed_viewer'):
                trainer_window.tabbed_viewer = None
            self.win.destroy()
        self.win.protocol("WM_DELETE_WINDOW", on_close)

    def _close_tab(self, tid):
        """Remove a tab and its associated data."""
        for i, tab in enumerate(self.tabs):
            if tab['id'] == tid:
                if tab['state']['live_id']:
                    try: self.win.after_cancel(tab['state']['live_id'])
                    except: pass
                self.notebook.forget(tab['frame'])
                tab['frame'].destroy()
                del self.tabs[i]
                break

    # ---- physical / virtual address helpers --------------------------------
    def _vmode(self, state):
        v = state.get('virt_var')
        return bool(v.get()) if v is not None else False

    def _phys_of(self, state, addr):
        """Active-space address -> physical offset, or None if unmapped."""
        if not self._vmode(state):
            return addr
        pm = self.engine.pagemap
        return None if pm is None else pm.to_phys(addr)

    def _read_span(self, state, addr, length, mem_file):
        """
        Read a run of bytes in the active address space.

        In virtual mode this cannot be one read: consecutive virtual pages map
        to scattered physical ones, so the span is gathered a page at a time and
        unmapped pages come back flagged rather than silently zero-filled.
        Returns (data, mask) with mask[i] false where nothing is mapped.
        """
        if not self._vmode(state):
            data = self.engine.read_mem(
                self.engine.xbox_ram_base + addr, length, mem_file)
            return data, bytearray(b'\x01') * len(data)
        pm = self.engine.pagemap
        out, mask = bytearray(), bytearray()
        a, rem = addr, length
        while rem > 0 and a <= 0xFFFFFFFF:
            take = min(0x1000 - (a & 0xFFF), rem)
            p = pm.to_phys(a) if pm is not None else None
            if p is None:
                out += b'\x00' * take
                mask += b'\x00' * take
            else:
                out += self.engine.read_mem(
                    self.engine.xbox_ram_base + p, take, mem_file)
                mask += b'\x01' * take
            a += take
            rem -= take
        return bytes(out), mask

    def _write_at(self, state, addr, data, mem_file=None):
        p = self._phys_of(state, addr)
        if p is None:
            return False
        self.engine.write_mem(self.engine.xbox_ram_base + p, data, mem_file)
        return True

    def _write_span(self, state, addr, data, mem_file=None):
        """
        Write a run of bytes in the active address space, page by page.

        The mirror of _read_span, and needed for the same reason: consecutive
        virtual pages are scattered physically, so a multi-byte write handed to
        one translated address lands in the wrong place the moment it crosses a
        page boundary. Unmapped pages are skipped and counted rather than
        redirected somewhere harmless-looking.

        Returns (bytes_written, [unmapped addresses]).
        """
        if not self._vmode(state):
            self.engine.write_mem(self.engine.xbox_ram_base + addr,
                                  bytes(data), mem_file)
            return len(data), []
        written, holes = 0, []
        a, i = addr, 0
        while i < len(data):
            take = min(0x1000 - (a & 0xFFF), len(data) - i)
            p = self._phys_of(state, a)
            if p is None:
                holes.append(a)
            else:
                self.engine.write_mem(self.engine.xbox_ram_base + p,
                                      bytes(data[i:i + take]), mem_file)
                written += take
            a += take
            i += take
        return written, holes

    def _ensure_pagemap(self):
        """Build the page map if it is not up yet. Returns True when usable."""
        if self.engine.pagemap is None:
            mf = None
            try:
                if self.engine.os_type == "Linux":
                    mf = open(f"/proc/{self.engine.pid}/mem", "rb")
                self.engine.refresh_pagemap(mf)
            except Exception:
                pass
            finally:
                if mf:
                    try: mf.close()
                    except Exception: pass
        return self.engine.pagemap is not None

    def add_tab_at(self, dest, virtual=False, title=None):
        """
        Open a tab at `dest`, switching it into Virtual mode when asked.

        `dest` is an address in the space named by `virtual` - it is NOT
        translated here. That is the whole point: the caller already knows
        which space it holds, and re-deriving it loses information.

        Previously this set virt_var and then fired on_virt_toggle() to make
        the tab re-read through the page tables. That was wrong in three ways
        and is why jumps landed in the wrong place:

          * on_virt_toggle exists to convert the address currently on screen
            from one space to the other. Firing it on a tab already holding a
            virtual address translated that address a second time, as though
            it were physical. Whatever fell out was then partially overwritten,
            so the visible result depended on whether the bogus intermediate
            happened to be mapped.
          * The refresh it performs runs against that bogus intermediate.
          * When the double translation returned None it took the
            "unmapped" branch and reset the view to 0x00010000, which is the
            "it just went somewhere else entirely" case.

        Switching space and choosing an address are now separate operations
        (set_space vs. the assignments below), so neither can corrupt the other.
        """
        if virtual and not self._ensure_pagemap():
            messagebox.showerror(
                "Virtual addressing unavailable",
                "The guest page tables could not be read.\n"
                "The game may not be running yet.")
            return None

        self.add_tab(offset=dest, title=title)
        st = self.tabs[-1]['state']

        # Set the address space first, without translating anything.
        if virtual and st.get('set_space'):
            st['set_space'](True)

        # Align the view origin to a row boundary but keep the caret on the
        # exact byte asked for. Truncating the address itself (the old
        # behaviour, and still what follow_pointer did) silently moved the
        # target by up to 15 bytes, which matters when the thing being
        # inspected is a field inside a struct.
        st['offset'] = dest & 0xFFFFFFF0
        st['keyboard_focused_byte_addr'] = dest
        st['selected_byte_start'] = dest
        st['selected_byte_end'] = dest
        st['keyboard_nibble_flip'] = 0
        # Tells the deferred initial_highlight not to overwrite this.
        st['cursor_pinned'] = True
        if st.get('addr_entry') is not None:
            st['addr_entry'].delete(0, tk.END)
            st['addr_entry'].insert(0, f"0x{dest:08X}")

        # The tab's widgets were created a moment ago and have not been laid
        # out, so winfo_width()/winfo_height() still report 1. refresh_view
        # derives bytes-per-row and row-count from those, so drawing now
        # produces a 1-byte-wide, 2-row view and places the highlight using
        # that geometry. A later <Configure> redraws the hex correctly but does
        # not always re-place the caret - which is exactly the intermittent
        # "sometimes it doesn't go to the right place" behaviour.
        try:
            self.win.update_idletasks()
        except Exception:
            pass
        if st.get('refresh'):
            st['refresh']()
        return st

    def add_tab(self, offset=0, title=None):
        """Create a new hex viewer tab starting at the given 'offset'."""
        import struct
        tid = self.next_tab_id
        self.next_tab_id += 1
        if title is None: title = f"Tab {tid}"

        tab_frame = tk.Frame(self.notebook, bg="#151515")
        self.notebook.add(tab_frame, text=title)
        self.notebook.select(tab_frame)

        max_bounds = self.engine.xbox_ram_size_mb * 1024 * 1024

        # Navigation bar
        nav_top = tk.Frame(tab_frame, bg="#212121")
        nav_top.pack(fill="x", pady=2)
        row1 = tk.Frame(nav_top, bg="#212121")
        row1.pack(fill="x", anchor="w", padx=5, pady=2)
        tk.Label(row1, text="Go to Hex Offset: ", fg="#FFFFFF", bg="#212121",
                 font=("Helvetica",9,"bold")).pack(side="left")
        addr_entry = tk.Entry(row1, width=14, bg="#424242", fg="#FFFFFF",
                              insertbackground="white", bd=0,
                              font=("Courier",10,"bold"))
        addr_entry.insert(0, f"0x{offset:08X}")
        addr_entry.pack(side="left", padx=2)
        tk.Button(row1, text="Jump", bg="#FF9800", fg="#000000",
                  font=("Helvetica",8,"bold"), relief="flat", padx=8,
                  command=lambda: self._jump(tid, addr_entry)).pack(side="left", padx=5)

        region_var = tk.StringVar(value="")
        region_box = ttk.Combobox(row1, textvariable=region_var, width=34,
                                  state="readonly",
                                  values=[r[0] for r in XBOX_REGIONS])
        region_box.pack(side="right", padx=5)
        tk.Label(row1, text="Region: ", fg="#4FC3F7", bg="#212121",
                 font=("Helvetica",8,"bold")).pack(side="right")

        def on_region(entry):
            label, addr, is_virtual, backed = entry
            if is_virtual and not virt_var.get():
                virt_var.set(True)
                on_virt_toggle()          # builds the page map, rebases bounds
                if not virt_var.get():
                    return                # page tables unavailable; it warned
            elif not is_virtual and virt_var.get():
                virt_var.set(False)
                on_virt_toggle()
            state['offset'] = addr & 0xFFFFFFF0
            state['keyboard_focused_byte_addr'] = state['offset']
            state['selected_byte_start'] = state['offset']
            state['selected_byte_end'] = state['offset']
            addr_entry.delete(0, tk.END)
            addr_entry.insert(0, f"0x{state['offset']:08X}")
            refresh_view()
            if not backed:
                messagebox.showinfo(
                    "Not backed by RAM",
                    f"{label.strip()} is identity-mapped at physical "
                    "0xF0000000 or above,\nwhich is past the end of Xbox RAM. "
                    "xemu keeps it in a separate\nhost allocation, so the "
                    "viewer shows ?? here rather than\nfabricating data.")

        def _refresh_regions():
            """Static architectural entries plus whatever is really mapped."""
            vals = [r[0] for r in XBOX_REGIONS]
            state['regions'] = list(XBOX_REGIONS)
            pm = self.engine.pagemap
            if pm is not None:
                vals.append("--- detected this session ---")
                state['regions'].append(
                    ("--- detected this session ---", None, False, True))
                for a, b, p in pm.regions()[:14]:
                    mb = (b - a) / 1048576.0
                    lbl = f"{a:08X}  mapped {mb:6.2f} MB  -> phys {p:08X}"
                    vals.append(lbl)
                    state['regions'].append((lbl, a, True, True))
            region_box.config(values=vals)

        def on_region_sel(_evt=None):
            label = region_var.get()
            table = state.get('regions') or XBOX_REGIONS
            entry = next((r for r in table if r[0] == label), None)
            if entry is not None and entry[1] is not None:
                on_region(entry)

        region_box.bind("<<ComboboxSelected>>", on_region_sel)

        row2 = tk.Frame(nav_top, bg="#212121")
        row2.pack(fill="x", anchor="w", padx=5, pady=2)
        tk.Label(row2, text="Endian: ", fg="#FFFFFF", bg="#212121",
                 font=("Helvetica",9,"bold")).pack(side="left")
        endian_var = tk.StringVar(value="Little Endian (Default)")
        opt_endian = tk.OptionMenu(row2, endian_var,
                                   "Little Endian (Default)",
                                   "Big Endian (Reversed)")
        opt_endian.config(font=("Helvetica",8,"bold"), bg="#424242",
                          fg="#E0E0E0", highlightthickness=0,
                          activebackground="#616161")
        opt_endian.pack(side="left", padx=4)
        bind_wheel_cycle(opt_endian,
                         ["Little Endian (Default)", "Big Endian (Reversed)"],
                         endian_var.get, endian_var.set)

        tk.Label(row2, text="  Interval (ms): ", fg="#FFFFFF", bg="#212121",
                 font=("Helvetica",9)).pack(side="left")
        live_var = tk.BooleanVar(value=self.tw._mem_live_default)
        tk.Checkbutton(row2, text="Live", variable=live_var,
                       font=("Helvetica",9), fg="#FFFFFF", bg="#212121",
                       selectcolor="#424242", activebackground="#212121",
                       activeforeground="#FFFFFF").pack(side="left", padx=5)
        virt_var = tk.BooleanVar(value=False)

        def on_virt_toggle():
            nonlocal max_bounds
            if virt_var.get():
                if self.engine.pagemap is None:
                    mf = open(f"/proc/{self.engine.pid}/mem", "rb") \
                         if self.engine.os_type == "Linux" else None
                    try:
                        self.engine.refresh_pagemap(mf)
                    finally:
                        if mf: mf.close()
                if self.engine.pagemap is None:
                    virt_var.set(False)
                    messagebox.showerror(
                        "Virtual addressing unavailable",
                        "The guest page tables could not be read.\n"
                        "The game may not be running yet.")
                    return
                to_new = self.engine.pagemap.to_virt
                fallback = 0x00010000
                max_bounds = 0x100000000
            else:
                pm = self.engine.pagemap
                to_new = pm.to_phys if pm else (lambda a: None)
                fallback = 0
                max_bounds = self.engine.xbox_ram_size_mb * 1024 * 1024

            # Follow the CURSOR, not the view origin. Translating only the
            # origin and then resetting the cursor to it is what made the
            # highlight jump to the top-left (or to 0 when the origin had no
            # mapping). Keeping the cursor's exact screen position means the
            # same byte stays under the marker, so the two views line up.
            cur = state['keyboard_focused_byte_addr']
            if cur is None:
                cur = state['selected_byte_start']
            if cur is None:
                cur = state['offset']
            rel = cur - state['offset']            # byte offset within the view
            sel_lo, sel_hi = state['selected_byte_start'], state['selected_byte_end']
            span = (sel_hi - sel_lo) if (sel_lo is not None and
                                         sel_hi is not None) else 0

            new_cur = to_new(cur)
            if new_cur is None:
                # Cursor itself isn't mapped in the target space; fall back to
                # the view origin so the jump is at least anchored nearby.
                new_org = to_new(state['offset'])
                state['offset'] = (new_org if new_org is not None
                                   else fallback) & 0xFFFFFFF0
                new_cur = state['offset']
                span = 0
            else:
                origin = new_cur - rel
                if origin < 0:
                    origin = 0
                state['offset'] = origin

            state['keyboard_focused_byte_addr'] = new_cur
            state['selected_byte_start'] = new_cur
            state['selected_byte_end'] = new_cur + span
            state['keyboard_nibble_flip'] = 0
            addr_entry.delete(0, tk.END)
            addr_entry.insert(0, f"0x{state['offset']:08X}")
            _refresh_regions()
            refresh_view()

        def set_space(virtual):
            """
            Switch address space WITHOUT touching the current address.

            on_virt_toggle translates the on-screen address as it flips; that
            is right when the user clicks the tickbox (they want to keep
            looking at the same byte) and wrong when a caller already has an
            address in the target space. This is the no-translation half, and
            it also updates max_bounds - which matters because refresh_view
            stops drawing rows at max_bounds, so a virtual address above the
            physical RAM size (the 0x8xxxxxxx and 0xD0xxxxxx kernel windows)
            renders as an empty pane if the bound is left at physical.
            """
            nonlocal max_bounds
            virt_var.set(bool(virtual))
            max_bounds = (0x100000000 if virtual
                          else self.engine.xbox_ram_size_mb * 1024 * 1024)
            try:
                _refresh_regions()
            except Exception:
                pass

        tk.Checkbutton(row2, text="Virtual", variable=virt_var,
                       command=on_virt_toggle,
                       font=("Helvetica",9), fg="#4FC3F7", bg="#212121",
                       selectcolor="#424242", activebackground="#212121",
                       activeforeground="#4FC3F7").pack(side="left", padx=5)

        live_interval_var = tk.StringVar(value=str(self.tw._mem_live_interval))
        interval_entry = tk.Entry(row2, width=5, bg="#424242", fg="#FFFFFF",
                                  insertbackground="white", bd=0,
                                  textvariable=live_interval_var)
        def update_global_live_interval(*args):
            try: self.tw._mem_live_interval = int(live_interval_var.get())
            except: pass

        def remember_live(*args):
            self.tw._mem_live_default = bool(live_var.get())
        live_var.trace_add("write", remember_live)
        live_interval_var.trace_add("write", update_global_live_interval)
        interval_entry.pack(side="left", padx=2)

        hex_text = tk.Text(tab_frame, font=("Courier",10,"bold"),
                           bg="#151515", fg="#8A8A8A", bd=0,
                           highlightthickness=0, selectbackground="#007ACC",
                           selectforeground="#FFFFFF", insertbackground="white",
                           cursor="arrow", exportselection=0)
        hex_text.pack(fill="both", expand=True, padx=10, pady=5)
        hex_text.tag_configure("byte_select", background="#FF9800",
                               foreground="#000000")
        hex_text.tag_configure("ascii_select", background="#444444",
                               foreground="#FFFFFF")

        try:
            char_width = int(hex_text.tk.call(hex_text._w, "font", "measure",
                                              hex_text['font'], "0"))
        except: char_width = 8

        state = {
            'offset': offset,
            'selected_byte_start': None,
            'selected_byte_end': None,
            'keyboard_focused_byte_addr': None,
            'keyboard_nibble_flip': 0,
            'ascii_input_mode': False,
            'scroll_throttle_active': False,
            'scroll_release_timer_id': None,
            'live_id': None,
            'calculated_row_capacity': 16,
            'bytes_per_row': 16,
            'hex_start_col': 13,
            'ascii_start_col': 64,
            'endian_var': endian_var,
            'virt_var': virt_var,
            'live_var': live_var,
            'interval_entry': interval_entry,
            'addr_entry': addr_entry,
            'hex_text': hex_text,
            'char_width': char_width,
            'cursor_pinned': False,
            'refresh': None
        }

        # ----- Helper functions (with closures) -----
        def get_byte_index_from_mouse_coords(event):
            """Return the RAM offset of the byte under the mouse."""
            try:
                idx = hex_text.index(f"@{event.x},{event.y}")
                ln, col = map(int, idx.split('.'))
                bytes_per = state['bytes_per_row']
                hs = state['hex_start_col']
                aas = state['ascii_start_col']
                if hs <= col <= hs + (bytes_per - 1) * 3 + 1:
                    off = (col - hs) // 3
                    if off < bytes_per:
                        target = state['offset'] + (ln - 1) * bytes_per + off
                        if 0 <= target < max_bounds: return target
                elif aas <= col <= aas + bytes_per - 1:
                    off = col - aas
                    if off < bytes_per:
                        target = state['offset'] + (ln - 1) * bytes_per + off
                        if 0 <= target < max_bounds: return target
            except: pass
            return None

        def refresh_view():
            """Redraw the hex dump."""
            widget_width = hex_text.winfo_width() - 20
            cw = state['char_width']
            B = max(1, (widget_width // cw - 19) // 4) if cw > 0 else 16
            B = min(B, 128)
            state['bytes_per_row'] = B
            state['hex_start_col'] = 13
            state['ascii_start_col'] = 13 + 3 * B + 3

            widget_height = hex_text.winfo_height()
            cap = max(1, widget_height // 16 + 2)
            state['calculated_row_capacity'] = cap

            bytes_to_fetch = cap * B
            # open() on a dead pid raises ProcessLookupError. The viewer has
            # no useful way to render a process that is gone, so it leaves the
            # last dump on screen and waits for a reattach.
            try:
                mem_file = open(f"/proc/{self.engine.pid}/mem","rb") \
                           if self.engine.os_type == "Linux" else None
            except OSError:
                return
            chunk, cmask = self._read_span(state, state['offset'],
                                           bytes_to_fetch, mem_file)
            if mem_file: mem_file.close()
            hex_text.config(state="normal")
            hex_text.delete("1.0", tk.END)
            big = "Big Endian" in state['endian_var'].get()
            for row_idx in range(cap):
                ro = state['offset'] + row_idx * B
                if ro >= max_bounds: break
                row_data = chunk[row_idx*B:(row_idx+1)*B]
                row_mask = bytes(cmask[row_idx*B:(row_idx+1)*B])
                if len(row_data) < B:
                    row_data = row_data + b'\x00' * (B - len(row_data))
                    row_mask = row_mask + b'\x00' * (B - len(row_mask))
                row_bytes = bytearray(row_data)
                mask_b = bytearray(row_mask)
                if big:
                    for i in range(0, B, 4):
                        if i+4 <= B:
                            row_bytes[i:i+4] = reversed(row_bytes[i:i+4])
                            mask_b[i:i+4] = reversed(mask_b[i:i+4])
                prefix = f"0x{ro:08X} | "
                # Unmapped virtual pages print as ?? rather than zeros, so a
                # hole in the address space is never mistaken for real data.
                hex_parts = [f"{b:02X}" if m else "??"
                             for b, m in zip(row_bytes, mask_b)]
                hex_dump = " ".join(hex_parts).ljust(3*B - 1)
                ascii_dump = "".join(chr(b) if (m and 32 <= b <= 126) else "."
                                     for b, m in zip(row_bytes, mask_b))
                hex_text.insert(tk.END, f"{prefix}{hex_dump}    {ascii_dump}\n")
            hex_text.config(state="disabled")
            render_highlights()

        hex_text.bind("<Configure>", lambda e: refresh_view())

        def render_highlights():
            """Highlight the currently selected byte(s)."""
            hex_text.tag_remove("sel", "1.0", tk.END)
            hex_text.tag_remove("byte_select", "1.0", tk.END)
            hex_text.tag_remove("ascii_select", "1.0", tk.END)
            s = state['keyboard_focused_byte_addr'] if state['keyboard_focused_byte_addr'] is not None else state['selected_byte_start']
            e = state['keyboard_focused_byte_addr'] if state['keyboard_focused_byte_addr'] is not None else state['selected_byte_end']
            if s is None or e is None: return
            start, end = min(s, e), max(s, e)
            B = state['bytes_per_row']
            hs, aas = state['hex_start_col'], state['ascii_start_col']
            cap = state['calculated_row_capacity']
            for addr in range(start, end+1):
                rel = addr - state['offset']
                if 0 <= rel < cap * B:
                    row = rel // B + 1
                    col = rel % B
                    hex_c = hs + col * 3
                    ascii_c = aas + col
                    if hs <= hex_c <= hs + (B-1)*3 + 1:
                        hex_text.tag_add("byte_select", f"{row}.{hex_c}",
                                         f"{row}.{hex_c+2}")
                    if aas <= ascii_c <= aas + B - 1:
                        hex_text.tag_add("ascii_select", f"{row}.{ascii_c}",
                                         f"{row}.{ascii_c+1}")

        state['refresh'] = refresh_view
        # Exposed so other tabs can flip this one into virtual mode
        # (used by Follow Address, which opens a new tab).
        state['on_virt_toggle'] = on_virt_toggle
        state['set_space'] = set_space

        # Auto‑highlight first byte after initial draw
        def initial_highlight():
            # Fires 100 ms after the tab is built. If a caller has already
            # placed the caret deliberately (add_tab_at, _jump), leave it
            # alone - this used to run last and quietly drag the selection
            # back to the top of the view, undoing the jump that had just
            # been performed.
            if not state.get('cursor_pinned'):
                state['keyboard_focused_byte_addr'] = state['offset']
                state['selected_byte_start'] = state['offset']
                state['selected_byte_end'] = state['offset']
                state['keyboard_nibble_flip'] = 0
            render_highlights()
        self.win.after(100, initial_highlight)

        # Mouse click / drag / keyboard / clipboard / follow‑pointer handlers
        def on_click(event):
            hex_text.focus_set()
            addr = get_byte_index_from_mouse_coords(event)
            if addr is not None:
                state['selected_byte_start'] = addr
                state['selected_byte_end'] = addr
                state['keyboard_focused_byte_addr'] = addr
                state['keyboard_nibble_flip'] = 0
                try:
                    col = int(hex_text.index(f"@{event.x},{event.y}").split('.')[1])
                    state['ascii_input_mode'] = state['ascii_start_col'] <= col <= state['ascii_start_col'] + state['bytes_per_row'] - 1
                except: state['ascii_input_mode'] = False
                render_highlights()
            return "break"

        def on_drag(event):
            addr = get_byte_index_from_mouse_coords(event)
            if addr is not None and state['selected_byte_start'] is not None:
                state['selected_byte_end'] = addr
                # Clearing the caret unconditionally is why typing a value
                # often did nothing until an arrow key was pressed: <B1-Motion>
                # fires on a pixel of drift during an ordinary click, so the
                # address on_click had just set was thrown away again, and
                # on_key() returns early when it is None. Only a selection that
                # actually spans more than one byte has no single caret.
                if addr == state['selected_byte_start']:
                    state['keyboard_focused_byte_addr'] = addr
                else:
                    state['keyboard_focused_byte_addr'] = None
                render_highlights()
            return "break"

        def typing_in_a_field(event=None):
            """
            True when a text field owns the keyboard.

            on_key and on_arrow are bound to the TOPLEVEL, so every keystroke
            anywhere in the window reaches them - including the ones being
            typed into "Go to Hex Offset". Hex digits meant for that box were
            also being written into the selected byte in the dump below, and
            arrow keys meant for editing the text moved the hex caret.
            """
            w = event.widget if event is not None else None
            if not isinstance(w, (tk.Entry, tk.Text, ttk.Entry)) or w is None:
                w = self.win.focus_get()
            if w is hex_text:
                return False
            return isinstance(w, (tk.Entry, tk.Text, ttk.Entry, ttk.Combobox))

        def on_key(event):
            if typing_in_a_field(event): return
            if state['keyboard_focused_byte_addr'] is None: return
            ch = event.char
            if not ch: return
            is_hex = ch.lower() in '0123456789abcdef'
            if not (is_hex or ch.isprintable()): return
            mem_file = open(f"/proc/{self.engine.pid}/mem","rb+") \
                       if self.engine.os_type == "Linux" else None
            if state['ascii_input_mode'] and ch.isprintable():
                for b in ch.encode('utf-8'):
                    if state['keyboard_focused_byte_addr'] >= max_bounds: break
                    self._write_at(state, state['keyboard_focused_byte_addr'],
                                          bytes([b]), mem_file)
                    state['keyboard_focused_byte_addr'] += 1
                state['keyboard_focused_byte_addr'] = min(state['keyboard_focused_byte_addr'], max_bounds-1)
                state['selected_byte_start'] = state['keyboard_focused_byte_addr']
                state['selected_byte_end'] = state['keyboard_focused_byte_addr']
            else:
                if not is_hex:
                    if mem_file: mem_file.close()
                    return
                val = int(ch.lower(), 16)
                cur_raw, _ = self._read_span(state, state['keyboard_focused_byte_addr'], 1, mem_file)
                cur_byte = cur_raw[0] if cur_raw else 0
                if state['keyboard_nibble_flip'] == 0:
                    new_byte = (val << 4) | (cur_byte & 0x0F)
                    state['keyboard_nibble_flip'] = 1
                else:
                    new_byte = (cur_byte & 0xF0) | val
                    state['keyboard_nibble_flip'] = 0
                self._write_at(state, state['keyboard_focused_byte_addr'],
                                      bytes([new_byte]), mem_file)
                if state['keyboard_nibble_flip'] == 0:
                    state['keyboard_focused_byte_addr'] += 1
                state['selected_byte_start'] = state['keyboard_focused_byte_addr']
                state['selected_byte_end'] = state['keyboard_focused_byte_addr']
            if mem_file: mem_file.close()
            refresh_view()
            self.tw.update_table_view()

        def on_arrow(event):
            if typing_in_a_field(event): return
            cur = state['keyboard_focused_byte_addr'] if state['keyboard_focused_byte_addr'] is not None else (
                  state['selected_byte_end'] if state['selected_byte_end'] is not None else (
                  state['selected_byte_start'] if state['selected_byte_start'] is not None else state['offset']))
            step = {'Up': -state['bytes_per_row'], 'Down': state['bytes_per_row'],
                    'Left': -1, 'Right': 1}.get(event.keysym, 0)
            new_addr = cur + step
            if 0 <= new_addr < max_bounds:
                state['keyboard_focused_byte_addr'] = new_addr
                state['selected_byte_start'] = new_addr
                state['selected_byte_end'] = new_addr
                state['keyboard_nibble_flip'] = 0
                if new_addr < state['offset']:
                    state['offset'] = (new_addr // state['bytes_per_row']) * state['bytes_per_row']
                elif (new_addr - state['offset']) >= state['calculated_row_capacity'] * state['bytes_per_row']:
                    state['offset'] = ((new_addr // state['bytes_per_row']) - state['calculated_row_capacity'] + 2) * state['bytes_per_row']
                refresh_view()
            return "break"

        def on_scroll(event):
            state['scroll_throttle_active'] = True
            if state['scroll_release_timer_id']:
                self.win.after_cancel(state['scroll_release_timer_id'])
            state['scroll_release_timer_id'] = self.win.after(
                250, lambda: state.update({'scroll_throttle_active': False}))
            delta = -1 if (event.num==4 or event.delta>0) else 1
            state['offset'] = max(0, state['offset'] + delta * state['bytes_per_row'])
            refresh_view()

        def on_page(event):
            state['scroll_throttle_active'] = True
            if state['scroll_release_timer_id']:
                self.win.after_cancel(state['scroll_release_timer_id'])
            state['scroll_release_timer_id'] = self.win.after(
                250, lambda: state.update({'scroll_throttle_active': False}))
            cap = state['calculated_row_capacity'] - 4
            if event.keysym == "Prior":
                state['offset'] = max(0, state['offset'] - cap * state['bytes_per_row'])
            else:
                state['offset'] += cap * state['bytes_per_row']
            refresh_view()

        def copy_bytes(event=None):
            s = state['keyboard_focused_byte_addr'] if state['keyboard_focused_byte_addr'] is not None else (
                min(state['selected_byte_start'], state['selected_byte_end']) if state['selected_byte_start'] is not None and state['selected_byte_end'] is not None else None)
            e = state['keyboard_focused_byte_addr'] if state['keyboard_focused_byte_addr'] is not None else (
                max(state['selected_byte_start'], state['selected_byte_end']) if state['selected_byte_start'] is not None and state['selected_byte_end'] is not None else None)
            if s is None or e is None: return
            length = e - s + 1
            mem_file = open(f"/proc/{self.engine.pid}/mem","rb") \
                       if self.engine.os_type == "Linux" else None
            chunk, mask = self._read_span(state, s, length, mem_file)
            if mem_file: mem_file.close()
            # An unmapped byte reads back as 00, and copying that as "00" would
            # turn a hole into real data on the next paste. "??" keeps the hole
            # visible, and paste_bytes skips it, so copy -> paste round-trips
            # exactly even across an unmapped page.
            out = " ".join(f"{b:02X}" if (i < len(mask) and mask[i]) else "??"
                           for i, b in enumerate(chunk))
            self.tw.clipboard_clear()
            self.tw.clipboard_append(out)

        def paste_bytes(event=None):
            s = state['keyboard_focused_byte_addr'] if state['keyboard_focused_byte_addr'] is not None else state['selected_byte_start']
            if s is None: return
            try: raw = self.tw.clipboard_get().strip()
            except: return
            tokens = raw.replace(",", " ").replace("\n", " ").split()
            # Runs are built so that a skipped byte does not shift everything
            # after it. Dropping an unparseable token from a flat buffer, which
            # is what this used to do, silently pastes the rest one byte early -
            # far worse than refusing it.
            runs, cur, skipped, bad = [], bytearray(), 0, 0
            pos = 0
            for t in tokens:
                if t in ("??", "--", "..", "__"):
                    if cur:
                        runs.append((pos - len(cur), bytes(cur)))
                        cur = bytearray()
                    pos += 1
                    skipped += 1
                    continue
                try:
                    v = int(t[2:], 16) if t.lower().startswith("0x") else int(t, 16)
                except ValueError:
                    bad += 1
                    continue
                if not 0 <= v <= 0xFF:
                    bad += 1
                    continue
                cur.append(v)
                pos += 1
            if cur:
                runs.append((pos - len(cur), bytes(cur)))
            total = pos
            if not runs:
                return
            if bad:
                messagebox.showerror(
                    "Paste",
                    f"{bad} clipboard token(s) are not hex bytes. Nothing was "
                    f"written - pasting the rest would land at the wrong "
                    f"offsets.", parent=self.win)
                return
            if s + total > max_bounds:
                messagebox.showerror(
                    "Paste",
                    f"{total} byte(s) from 0x{s:08X} runs past the end of the "
                    f"address space.", parent=self.win)
                return
            mem_file = open(f"/proc/{self.engine.pid}/mem","rb+") \
                       if self.engine.os_type == "Linux" else None
            written, holes = 0, []
            try:
                for rel, blob in runs:
                    w, h = self._write_span(state, s + rel, blob, mem_file)
                    written += w
                    holes += h
            finally:
                if mem_file: mem_file.close()
            if holes:
                messagebox.showwarning(
                    "Paste",
                    f"Wrote {written} of {total - skipped} byte(s). "
                    f"{len(holes)} page(s) in that range are not mapped, "
                    f"starting at 0x{holes[0]:08X}, and were skipped.",
                    parent=self.win)
            new_addr = min(s + total, max_bounds-1)
            state['keyboard_focused_byte_addr'] = new_addr
            state['selected_byte_start'] = new_addr
            state['selected_byte_end'] = new_addr
            state['keyboard_nibble_flip'] = 0
            refresh_view()
            self.tw.update_table_view()

        def selected_span():
            """(start, length) of the current selection, or the cursor byte."""
            a = state['selected_byte_start']
            b = state['selected_byte_end']
            if a is None:
                a = state['keyboard_focused_byte_addr']
                b = a
            if a is None:
                return None, 0
            if b is None:
                b = a
            lo, hi = (a, b) if a <= b else (b, a)
            return lo, (hi - lo) + 1

        def build_popup_menu(event):
            menu = tk.Menu(self.tw, tearoff=0, bg="#424242", fg="#FFFFFF",
                           activebackground="#FF9800", activeforeground="#000000")

            def follow_pointer():
                s = state['keyboard_focused_byte_addr'] \
                    if state['keyboard_focused_byte_addr'] is not None \
                    else state['selected_byte_start']
                if s is None: return
                try:
                    mem_file = open(f"/proc/{self.engine.pid}/mem", "rb") \
                               if self.engine.os_type == "Linux" else None
                except Exception:
                    mem_file = None
                raw, _ = self._read_span(state, s, 4, mem_file)
                if mem_file: mem_file.close()
                if len(raw) < 4: return
                ptr = struct.unpack('<I', raw)[0]
                virt = self._vmode(state)
                if virt:
                    # Stored pointers are virtual, so follow them as-is.
                    pm = self.engine.pagemap
                    if pm is None or pm.to_phys(ptr) is None:
                        messagebox.showerror(
                            "Not mapped",
                            f"0x{ptr:08X} has no physical mapping.\n"
                            "It is either not a pointer, or its page is not "
                            "currently resident.")
                        return
                    dest = ptr
                else:
                    if not ((0x80000000 <= ptr < 0x80000000 + max_bounds) or
                            (0 <= ptr < max_bounds)):
                        return
                    dest = (ptr - 0x80000000 if ptr >= 0x80000000 else ptr)
                # Row alignment is applied to the view ORIGIN by add_tab_at;
                # the destination itself is kept exact. Truncating it here
                # moved the caret off the pointee by up to 15 bytes, so
                # following a chain landed near the target, not on it.
                # Open in a new tab so the origin stays put - following a chain
                # by hand means constantly wanting to look back at where the
                # pointer came from.
                self.add_tab_at(dest, virtual=bool(virt),
                                title=f"->{dest:08X}")

            def add_to_table():
                lo, ln = selected_span()
                if lo is None: return
                # Selection length picks a sensible default type.
                vtype = {1: "int8", 2: "int16", 4: "int32",
                         8: "float64"}.get(ln, "int32")
                if self._vmode(state):
                    pm = self.engine.pagemap
                    phys = pm.to_phys(lo) if pm else None
                    if phys is None:
                        messagebox.showerror(
                            "Not mapped",
                            f"Virtual 0x{lo:08X} has no physical mapping.")
                        return
                    desc = f"Viewer V:0x{lo:08X}"
                else:
                    phys = lo
                    desc = f"Viewer 0x{lo:08X}"
                self.engine.address_table.append([
                    phys, desc, vtype, False, "0", False, 0, [], phys, "",
                    self.engine._next_entry_id, False])
                self.engine._next_entry_id += 1
                self.tw._rebuild_table = True
                self.tw.update_table_view()

            def copy_address():
                lo, _ = selected_span()
                if lo is None: return
                self.win.clipboard_clear()
                self.win.clipboard_append(f"0x{lo:08X}")

            lo, ln = selected_span()
            label = (f"Add 0x{lo:08X} to Address Table ({ln} byte"
                     f"{'s' if ln != 1 else ''})") if lo is not None \
                    else "Add to Address Table"
            menu.add_command(label=label, command=add_to_table,
                             state="normal" if lo is not None else "disabled")
            menu.add_command(label="Copy Address", command=copy_address,
                             state="normal" if lo is not None else "disabled")
            menu.add_separator()
            menu.add_command(label="Follow Address (pointer) in New Tab",
                             command=follow_pointer)
            popup_menu(menu, event.x_root, event.y_root)

        hex_text.bind("<ButtonPress-1>", on_click)
        hex_text.bind("<B1-Motion>", on_drag)
        hex_text.bind("<Button-3>", build_popup_menu)
        self.win.bind("<Key>", on_key)
        for sym in ("Up","Down","Left","Right"):
            self.win.bind(f"<KeyPress-{sym}>", on_arrow)
        # Bound to the hex widget, not the toplevel: on the window these fired
        # even while an address or interval Entry had focus, so Ctrl+V in a
        # text field also wrote the clipboard into game RAM as bytes.
        hex_text.bind("<Control-c>", copy_bytes)
        hex_text.bind("<Control-v>", paste_bytes)
        # Exposed on the tab state so the context menu and the tests can reach
        # them; they were previously only reachable through a key binding on one
        # widget, which is also why the virtual-mode paste bug went unnoticed.
        state['copy_bytes'] = copy_bytes
        state['paste_bytes'] = paste_bytes
        hex_text.bind("<MouseWheel>", on_scroll)
        hex_text.bind("<Button-4>", on_scroll)
        hex_text.bind("<Button-5>", on_scroll)
        hex_text.bind("<Prior>", on_page)
        hex_text.bind("<Next>", on_page)

        def live_loop():
            if not self.win.winfo_exists(): return
            # The reschedule has to happen even if refresh_view() throws.
            # With it sitting after the call, one bad refresh silently ended
            # live mode for the rest of the session.
            try: ms = max(10, min(1000, int(state['interval_entry'].get())))
            except: ms = 100
            state['live_id'] = self.win.after(ms, live_loop)
            if state['live_var'].get() and not state['scroll_throttle_active']:
                refresh_view()
        live_loop()

        tab_data = {'id': tid, 'state': state, 'frame': tab_frame}
        self.tabs.append(tab_data)
        self.notebook.tab(tab_frame, text=title)
        self.win.after(50, refresh_view)
        self.notebook.select(tab_frame)
        return tab_data

    def _jump(self, tid, entry):
        """Jump to a new offset in a specific tab."""
        for tab in self.tabs:
            if tab['id'] == tid:
                try:
                    txt = entry.get().strip()
                    base = 16 if (txt.lower().startswith("0x") or
                                  any(c in txt.lower() for c in 'abcdef')) else 10
                    target = int(txt, base)
                    if target < 0: target = 0
                    st = tab['state']
                    if self._vmode(st):
                        # Virtual mode: accept any mapped address, including
                        # the 0x8xxxxxxx and 0xD0xxxxxx kernel windows, which
                        # fall outside the physical RAM bound below.
                        pm = self.engine.pagemap
                        limit = (target <= 0xFFFFFFFF and pm is not None
                                 and pm.to_phys(target) is not None)
                    else:
                        limit = target < self.engine.xbox_ram_size_mb * 1024 * 1024
                    if limit:
                        # Origin snaps to a row; the caret keeps the exact
                        # address typed. Rounding the caret as well meant
                        # entering a struct field address selected the start
                        # of its row instead of the field.
                        st['offset'] = target & 0xFFFFFFF0
                        st['keyboard_focused_byte_addr'] = target
                        st['selected_byte_start'] = target
                        st['selected_byte_end'] = target
                        st['keyboard_nibble_flip'] = 0
                        st['cursor_pinned'] = True
                        st['refresh']()
                        # Re-place once layout has settled; on a tab created
                        # moments ago the geometry used by the first pass can
                        # still be the pre-layout 1x1.
                        self.win.after(50, lambda s=st: s['refresh']())
                    else:
                        space = "virtual" if self._vmode(st) else "physical"
                        messagebox.showerror(
                            "Out of range",
                            f"0x{target:08X} is not a valid {space} address.\n"
                            "Nothing was changed.")
                except Exception:
                    pass
                break
