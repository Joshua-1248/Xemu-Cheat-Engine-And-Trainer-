"""Main trainer window (scan UI, cheat table, pointer wizard).

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
from .disasm_window import DisassemblyWindow  # noqa: F401
from .gdb_broker import GdbWatchWindow  # noqa: F401
from .memviewer import TabbedMemoryViewer  # noqa: F401
from .pagemap import PointerMap, XboxPageMap, scan_chains, scan_chains_verified  # noqa: F401
from .regions import KSEG_BASE, XBOX_SCAN_REGIONS, describe_address, detect_xbe_region, parse_xbe_sections  # noqa: F401
from .ui_widgets import bind_wheel, bind_wheel_cycle, bind_wheel_number, install_clipboard_fix, install_global_wheel, popup_menu, sane_geometry  # noqa: F401


class TrainerWindow(tk.Tk):
    """
    Main application window. Contains all UI controls and orchestrates
    scanning, freezing, pointer finding, and table management.
    """

    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.title("Xemu Cheat Engine")

        # Configuration file for saving window position & settings
        self._config = configparser.ConfigParser()
        self._config_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "xemu_cheat_engine.ini")

        # Restore saved window geometry
        saved_geom = None
        if os.path.exists(self._config_file):
            try:
                self._config.read(self._config_file, encoding='utf-8')
                if 'main_window' in self._config:
                    x = self._config.getint('main_window', 'x', fallback=None)
                    y = self._config.getint('main_window', 'y', fallback=None)
                    w = self._config.getint('main_window', 'width', fallback=None)
                    h = self._config.getint('main_window', 'height', fallback=None)
                    if None not in (x, y, w, h):
                        saved_geom = sane_geometry(self, x, y, w, h)
            except: pass
        if saved_geom: self.geometry(saved_geom)
        else:          self.geometry("780x680")

        self.configure(bg="#212121")

        # Internal state
        self.ui_row_editing_locks = {}      # prevents value updates while user types
        self._rebuild_table = True          # flag to force full address‑table rebuild
        # Address-table selection. _selected_entry_id is the LAST row clicked
        # (what Ctrl+C copies); _selected_entry_ids is the full set, which may
        # hold several rows at once. The set is the authority for bulk actions;
        # the single id is kept in step so existing single-row code still works.
        self._selected_entry_id = None
        self._selected_entry_ids = set()
        self._sel_anchor = None             # Shift+click ranges extend from here
        self._row_order = []                # entry ids in on-screen order
        self.groups = []                    # list of group names (order matters)
        self.collapsed_groups = {}          # which groups are collapsed
        # Pointer finder settings
        self.ptr_negative_offsets = tk.BooleanVar(value=False)
        self.ptr_tolerance = tk.IntVar(value=0)
        self.ptr_max_offset = tk.StringVar(value="1000")  # hex, struct size cap
        self.ptr_static_only = tk.BooleanVar(value=False)
        self.ptr_map_a = None
        self._mem_live_interval = 100       # ms between memory viewer refreshes
        self._mem_live_default = False     # live refresh on by default?
        self._saved_main_sash = None
        self._saved_top_sash = None

        # Status bar at the top
        self.label_status = tk.Label(self, text="Detecting...",
                                     font=("Helvetica",10),
                                     fg="#B0BEC5", bg="#212121")
        self.label_status.pack(pady=10)

        self._build_gui()                   # construct all UI elements
        self._apply_saved_settings()       # restore saved refresh intervals
        self._apply_hover_to_all_buttons()
        self.initialize_engine()            # connect to Xemu & start freeze thread

    # ------------------------------------------------------------------
    def _apply_saved_settings(self):
        """Set the table refresh rate and memory‑viewer interval from config."""
        if 'refresh' in self._config and \
           self._config.has_option('refresh', 'table_ms'):
            try:
                self.table_refresh_interval.set(
                    self._config.getint('refresh', 'table_ms', fallback=500))
            except: pass
        if 'memory_viewer' in self._config and \
           self._config.has_option('memory_viewer', 'live_interval_ms'):
            try:
                self._mem_live_interval = self._config.getint(
                    'memory_viewer', 'live_interval_ms', fallback=100)
            except: pass
        if 'layout' in self._config:
            try:
                self._saved_main_sash = self._config.getint(
                    'layout', 'main_sash', fallback=None)
                self._saved_top_sash = self._config.getint(
                    'layout', 'top_sash', fallback=None)
            except Exception: pass
        if 'memory_viewer' in self._config and \
           self._config.has_option('memory_viewer', 'live_default'):
            try:
                self._mem_live_default = self._config.getboolean(
                    'memory_viewer', 'live_default', fallback=False)
            except: pass

    def _save_settings(self):
        """Store window geometry, refresh rates, and memory‑viewer geometry to .ini."""
        try:
            if 'main_window' not in self._config:
                self._config['main_window'] = {}
            geo = self.geometry().replace('+','x').split('x')
            if len(geo) >= 4:
                self._config['main_window']['width']  = geo[0]
                self._config['main_window']['height'] = geo[1]
                self._config['main_window']['x']      = geo[2]
                self._config['main_window']['y']      = geo[3]
            if 'refresh' not in self._config:
                self._config['refresh'] = {}
            self._config['refresh']['table_ms'] = str(self.table_refresh_interval.get())
            # The live interval is saved unconditionally. It used to live inside
            # the block below, so closing the memory viewer before quitting lost
            # the setting entirely.
            if 'memory_viewer' not in self._config:
                self._config['memory_viewer'] = {}
            self._config['memory_viewer']['live_interval_ms'] = \
                str(self._mem_live_interval)
            self._config['memory_viewer']['live_default'] = \
                str(bool(self._mem_live_default))
            try:
                if 'layout' not in self._config:
                    self._config['layout'] = {}
                self._config['layout']['main_sash'] = str(
                    self.main_split.sash_coord(0)[1])
                self._config['layout']['top_sash'] = str(
                    self.top_split.sash_coord(0)[0])
            except Exception:
                pass
            if hasattr(self, 'tabbed_viewer') and self.tabbed_viewer and \
               self.tabbed_viewer.win.winfo_exists():
                geo2 = self.tabbed_viewer.win.geometry().replace('+','x').split('x')
                if len(geo2) >= 4:
                    self._config['memory_viewer']['width']  = geo2[0]
                    self._config['memory_viewer']['height'] = geo2[1]
                    self._config['memory_viewer']['x']      = geo2[2]
                    self._config['memory_viewer']['y']      = geo2[3]
            with open(self._config_file, 'w', encoding='utf-8') as f:
                self._config.write(f)
            xemu_privs.reclaim(self._config_file)
        except: pass

    def destroy(self):
        """Cleanly shut down: save settings, stop the freeze thread."""
        self._save_settings()
        self.engine.running = False
        # Cancel the queued timers before tearing the widgets down. Both
        # reschedule themselves, so without this they stay pending and fire
        # once more against a window that is already being destroyed.
        self._shutting_down = True
        for attr in ('_table_after_id', '_conn_after_id'):
            aid = getattr(self, attr, None)
            if aid is not None:
                try: self.after_cancel(aid)
                except Exception: pass
                setattr(self, attr, None)
        if self.engine.win_process_handle and self.engine.os_type == "Windows":
            ctypes.windll.kernel32.CloseHandle(self.engine.win_process_handle)
        super().destroy()

    # ---- GUI construction ------------------------------------------------
    def _build_gui(self):
        """Build all widgets: buttons, scan inputs, address table, memory viewer, etc."""
        # Top bar: Load / Save table buttons
        top_left = tk.Frame(self, bg="#212121")
        top_left.pack(fill="x", padx=5, pady=(5,0), anchor="w")
        self.btn_load = tk.Button(top_left, text="Load Table",
                                  command=self.load_table,
                                  font=("Helvetica",9,"bold"), bg="#009688",
                                  fg="white", state="disabled", relief="flat")
        self.btn_load.pack(side="left", padx=2)
        self.btn_save = tk.Button(top_left, text="Save Table",
                                  command=self.save_table,
                                  font=("Helvetica",9,"bold"), bg="#795548",
                                  fg="white", state="disabled", relief="flat")
        self.btn_save.pack(side="left", padx=2)

        # Session-wide tools live on the same row as Load/Save Table, but
        # right-aligned with a gap between the two groups so they do not read
        # as one continuous strip of unrelated buttons. Packed in reverse
        # because side="right" fills from the edge inwards.
        for attr, text, cmd, bg, fg, st in reversed((
                ("btn_save_ptr", "Save Pointer Map", self._save_ptr_map,
                 "#455A64", "white", "normal"),
                ("btn_load_ptr", "Load Pointer Map", self._load_ptr_map,
                 "#00796B", "white", "normal"),
                ("btn_compare", "Compare Maps", self._compare_maps,
                 "#8BC34A", "black", "normal"),
                ("btn_dump_ram", "Dump RAM to File", self.dump_ram_to_file,
                 "#00838F", "white", "disabled"),
                ("btn_mem_view", "Memory Viewer",
                 lambda: self.open_mem_viewer(0),
                 "#607D8B", "white", "disabled"),
                ("btn_disasm", "Debugger", self.open_disassembler,
                 "#795548", "white", "disabled"),
                ("btn_patches", "Code Patches", self.open_code_patches,
                 "#5E35B1", "white", "disabled"))):
            b = tk.Button(top_left, text=text, command=cmd,
                          font=("Helvetica",8,"bold"), bg=bg, fg=fg,
                          state=st, relief="flat")
            b.pack(side="right", padx=2)
            setattr(self, attr, b)

        # Main area: left = scanner config & pointer finder, right = scan results & address table
        # Draggable split between the scan area and the address table, and
        # again between the scanner controls and the results list, so either
        # can be grown to see more rows.
        self.main_split = tk.PanedWindow(self, orient="vertical",
                                         bg="#111111", sashwidth=6,
                                         sashrelief="raised", bd=0,
                                         showhandle=False)
        self.main_split.pack(fill="both", expand=True)

        top_frame = tk.Frame(self.main_split, bg="#212121")
        self.main_split.add(top_frame, minsize=180, stretch="always")
        top_frame.grid_rowconfigure(0, weight=1)
        top_frame.grid_columnconfigure(0, weight=1)
        top_frame.grid_rowconfigure(0, weight=1)
        self.top_split = tk.PanedWindow(top_frame, orient="horizontal",
                                        bg="#111111", sashwidth=6,
                                        sashrelief="raised", bd=0,
                                        showhandle=False)
        self.top_split.grid(row=0, column=0, sticky="nsew", padx=10, pady=5)

        # ----- Scanner config frame (left) ---------------------------------
        scan_frame = tk.LabelFrame(self.top_split, text=" Memory Scanner Configurations ",
                                   font=("Helvetica",9,"bold"), bg="#212121",
                                   fg="#FF9800", bd=1)
        self.top_split.add(scan_frame, minsize=300, stretch="always")

        input_row = tk.Frame(scan_frame, bg="#212121")
        input_row.pack(pady=12, padx=10, fill="x")
        # Column 7 holds the HEX toggle and should not stretch.
        for i in range(7): input_row.grid_columnconfigure(i, weight=1)
        input_row.grid_columnconfigure(7, weight=0)

        self.scan_hex_mode_var = tk.BooleanVar(value=False)

        # Row 0 is a header strip naming what each control below it does - the
        # two dropdowns were bare, so "int8" and "Equal To" gave no clue which
        # was the value type and which the comparison.
        tk.Label(input_row, text="Value:", font=("Helvetica",8,"bold"),
                 fg="#B0BEC5", bg="#212121").grid(row=0, column=2,
                                                  sticky="w", padx=2)
        tk.Label(input_row, text="Value Type", font=("Helvetica",8,"bold"),
                 fg="#B0BEC5", bg="#212121").grid(row=0, column=5,
                                                  sticky="w", padx=2)
        tk.Label(input_row, text="Compare", font=("Helvetica",8,"bold"),
                 fg="#B0BEC5", bg="#212121").grid(row=0, column=6,
                                                  sticky="w", padx=2)

        # Value input field. The inline "Value:" label is gone - the header
        # strip above already names this column, and two labels for one field
        # just crowded the row.
        self.entry_value = tk.Entry(input_row, width=14, font=("Helvetica",10),
                                    bg="#424242", fg="#FFFFFF",
                                    insertbackground="white", bd=1)
        self.entry_value.grid(row=1, column=2, sticky="ew", padx=2)

        # "to" label and second value entry (for "Between" mode)
        self.lbl_to_spacer = tk.Label(input_row, text=" to ",
                                      font=("Helvetica",10), fg="#E0E0E0",
                                      bg="#212121")
        self.entry_value_max = tk.Entry(input_row, width=14,
                                        font=("Helvetica",10), bg="#424242",
                                        fg="#FFFFFF", insertbackground="white", bd=1)

        # Type dropdown (int8, int16, float, etc.)
        self.type_options = ["int8","int16","int32","float32","float64",
                             "String (UTF-8)","Array of Bytes"]
        self.dropdown_type_var = tk.StringVar(value="int8")
        self.opt_type = tk.OptionMenu(input_row, self.dropdown_type_var,
                                      *self.type_options)
        self.opt_type.config(font=("Helvetica",9), bg="#424242", fg="#E0E0E0",
                             highlightthickness=0, bd=0, activebackground="#616161")
        self.opt_type.grid(row=1, column=5, sticky="ew", padx=2)

        # Scan mode dropdown
        self.mode_options = ["Equal To","Not Equal To","Less Than","Greater Than",
                             "Between","Increased Value","Decreased Value",
                             "Increased Value By","Decreased Value By",
                             "Changed Value","Unchanged Value",
                             "Unknown Value Search"]
        self.dropdown_mode_var = tk.StringVar(value="Equal To")
        def on_mode_change(choice):
            """Show/hide the second value field for 'Between' mode."""
            if choice == "Between":
                self.lbl_to_spacer.grid(row=1, column=3, padx=2)
                self.entry_value_max.grid(row=1, column=4, sticky="ew", padx=2)
            else:
                self.lbl_to_spacer.grid_forget()
                self.entry_value_max.grid_forget()
        self.opt_mode = tk.OptionMenu(input_row, self.dropdown_mode_var,
                                      *self.mode_options, command=on_mode_change)
        self.opt_mode.config(font=("Helvetica",9), bg="#424242", fg="#E0E0E0",
                             highlightthickness=0, bd=0, activebackground="#616161")
        self.opt_mode.grid(row=1, column=6, sticky="ew", padx=2)

        # HEX now sits with the dropdowns it actually modifies, rather than
        # off on the far left where it read as a heading for the whole frame.
        hex_f = tk.Frame(input_row, bg="#212121")
        hex_f.grid(row=1, column=7, sticky="w", padx=(8,2))
        tk.Checkbutton(hex_f, text="HEX", variable=self.scan_hex_mode_var,
                       font=("Helvetica",8,"bold"), fg="#FF9800",
                       bg="#212121", selectcolor="#424242",
                       activebackground="#212121", activeforeground="#FF9800",
                       bd=0, highlightthickness=0,
                       command=self._on_hex_toggle).pack(side="left")

        # Mouse wheel to cycle dropdown values
        def cycle(event, var, opts):
            try: idx = opts.index(var.get())
            except: return
            if event.num==4 or event.delta>0: idx -= 1
            elif event.num==5 or event.delta<0: idx += 1
            else: return
            if 0 <= idx < len(opts): var.set(opts[idx])
        self.opt_type.bind("<MouseWheel>",
                           lambda e: cycle(e, self.dropdown_type_var, self.type_options))
        self.opt_type.bind("<Button-4>",
                           lambda e: cycle(e, self.dropdown_type_var, self.type_options))
        self.opt_type.bind("<Button-5>",
                           lambda e: cycle(e, self.dropdown_type_var, self.type_options))
        self.opt_mode.bind("<MouseWheel>",
                           lambda e: cycle(e, self.dropdown_mode_var, self.mode_options))
        self.opt_mode.bind("<Button-4>",
                           lambda e: cycle(e, self.dropdown_mode_var, self.mode_options))
        self.opt_mode.bind("<Button-5>",
                           lambda e: cycle(e, self.dropdown_mode_var, self.mode_options))

        # Scan region restriction
        self.scan_region_var = tk.StringVar(value=XBOX_SCAN_REGIONS[0][0])
        rg_row = tk.Frame(scan_frame, bg="#212121")
        rg_row.pack(fill="x", padx=10, pady=(4, 0))
        tk.Label(rg_row, text="Scan region: ", fg="#4FC3F7", bg="#212121",
                 font=("Helvetica", 8, "bold")).pack(side="left")
        self.opt_scan_region = ttk.Combobox(
            rg_row, textvariable=self.scan_region_var, state="readonly",
            width=24, values=[r[0] for r in XBOX_SCAN_REGIONS])
        self.opt_scan_region.pack(side="left", padx=4)
        self.opt_scan_region.bind("<<ComboboxSelected>>",
                                  lambda e: self._apply_scan_region())
        self.label_scan_region = tk.Label(rg_row, text="", fg="#B0BEC5",
                                          bg="#212121", font=("Helvetica", 8))
        self.label_scan_region.pack(side="left", padx=6)

        # Scan buttons (New / First / Next)
        btn_row = tk.Frame(scan_frame, bg="#212121")
        btn_row.pack(pady=5, padx=10, fill="x")
        self.btn_new = tk.Button(btn_row, text="New Scan", command=self.new_scan,
                                 font=("Helvetica",9,"bold"), bg="#f44336",
                                 fg="white", state="disabled", relief="flat")
        self.btn_new.pack(side="left", padx=2, expand=True, fill="x")
        self.btn_first = tk.Button(btn_row, text="First Scan",
                                   command=self.first_scan,
                                   font=("Helvetica",9,"bold"), bg="#4CAF50",
                                   fg="white", state="disabled", relief="flat")
        self.btn_first.pack(side="left", padx=2, expand=True, fill="x")
        self.btn_next = tk.Button(btn_row, text="Next Scan",
                                  command=self.next_scan,
                                  font=("Helvetica",9,"bold"), bg="#2196F3",
                                  fg="white", state="disabled", relief="flat")
        self.btn_next.pack(side="left", padx=2, expand=True, fill="x")

        # Manual address entry & Add button
        man_row = tk.Frame(scan_frame, bg="#212121")
        man_row.pack(pady=4, padx=10, fill="x")
        tk.Label(man_row, text="Address:", font=("Helvetica",10),
                 fg="#E0E0E0", bg="#212121").pack(side="left")
        self.entry_manual_addr = tk.Entry(man_row, width=12,
                                          font=("Courier",10,"bold"),
                                          bg="#424242", fg="#00FF00",
                                          insertbackground="white", bd=1)
        self.entry_manual_addr.pack(side="left", padx=5)
        self.entry_manual_addr.insert(0, "0x00000000")
        self.btn_add_manual = tk.Button(man_row, text="Add Address",
                                        command=self.add_manual,
                                        font=("Helvetica",8,"bold"),
                                        bg="#9C27B0", fg="white",
                                        state="disabled", relief="flat")
        self.btn_add_manual.pack(side="left", padx=2, expand=True, fill="x")
        self.btn_add_pointer = tk.Button(man_row, text="Add Pointer",
                                         command=self.add_pointer_entry,
                                         font=("Helvetica",8,"bold"),
                                         bg="#7B1FA2", fg="white",
                                         state="disabled", relief="flat")
        self.btn_add_pointer.pack(side="left", padx=2, expand=True, fill="x")

        # ----- Pointer Finder frame ----------------------------------------
        ptr_frame = tk.LabelFrame(scan_frame, text=" Pointer Finder ",
                                  font=("Helvetica",8,"bold"), bg="#212121",
                                  fg="#9C27B0", bd=1)
        ptr_frame.pack(pady=8, padx=10, fill="x")
        self.btn_ptr_wizard = tk.Button(ptr_frame,
                                        text="\u2b50 Find a Pointer (Guided)",
                                        command=self.pointer_wizard,
                                        font=("Helvetica",9,"bold"),
                                        bg="#7B1FA2", fg="white",
                                        state="disabled", relief="flat")
        self.btn_ptr_wizard.pack(fill="x", padx=10, pady=(6,2))
        tk.Label(ptr_frame, text="\u2500\u2500 or do it manually \u2500\u2500",
                 fg="#757575", bg="#212121",
                 font=("Helvetica",7)).pack(pady=(2,2))

        self.btn_stage1 = tk.Button(ptr_frame,
                                    text="Pointer Finder: Snapshot A (build index)",
                                    command=self.pointer_stage1,
                                    font=("Helvetica",8,"bold"), bg="#E91E63",
                                    fg="white", relief="flat")
        self.btn_stage1.pack(fill="x", padx=10, pady=4)
        self.btn_stage2 = tk.Button(ptr_frame,
                                    text="Pointer Finder: Snapshot B (scan + verify)",
                                    command=self.pointer_stage2,
                                    font=("Helvetica",8,"bold"), bg="#9C27B0",
                                    fg="white", relief="flat")
        self.btn_stage2.pack(fill="x", padx=10, pady=4)
        # Allow negative offsets checkbox
        tk.Checkbutton(ptr_frame, text="Allow Negative Offsets",
                       variable=self.ptr_negative_offsets,
                       bg="#212121", fg="#E0E0E0", selectcolor="#424242",
                       activebackground="#212121", activeforeground="#E0E0E0",
                       font=("Helvetica",8)).pack(anchor="w", padx=10, pady=2)

        tk.Checkbutton(ptr_frame, text="Only XBE-image bases (recommended)",
                       variable=self.ptr_static_only,
                       bg="#212121", fg="#E0E0E0", selectcolor="#424242",
                       activebackground="#212121", activeforeground="#E0E0E0",
                       font=("Helvetica",8)).pack(anchor="w", padx=10, pady=2)

        # Multi-level pointer scan controls
        ml_frame = tk.Frame(ptr_frame, bg="#212121")
        ml_frame.pack(fill="x", padx=10, pady=(4,2))
        tk.Label(ml_frame, text="Max Levels:", fg="#E0E0E0", bg="#212121",
                 font=("Helvetica",8)).pack(side="left")
        self.max_ptr_depth = tk.IntVar(value=3)
        depth_sb = tk.Spinbox(ml_frame, from_=1, to=10,
                              textvariable=self.max_ptr_depth, width=3,
                              bg="#424242", fg="#FFFFFF", font=("Helvetica",8),
                              bd=0)
        depth_sb.pack(side="left", padx=5)
        bind_wheel_number(depth_sb, self.max_ptr_depth, 1, 10, 1)

        # Max struct offset - the single most important tuning knob. Too small
        # and you miss the parent object; too large and every chain in RAM
        # "matches". 0x1000 is a sane default for most game objects.
        mo_f = tk.Frame(ptr_frame, bg="#212121")
        mo_f.pack(fill="x", padx=10, pady=2)
        tk.Label(mo_f, text="Max Struct Offset: 0x", fg="#E0E0E0", bg="#212121",
                 font=("Helvetica",8)).pack(side="left")
        mo_ent = tk.Entry(mo_f, textvariable=self.ptr_max_offset, width=6,
                          bg="#424242", fg="#FFFFFF", font=("Helvetica",8),
                          bd=0)
        mo_ent.pack(side="left", padx=5)
        # Hex field, and the useful range is powers of two - step by 0x100.
        bind_wheel_number(mo_ent, self.ptr_max_offset, 0x10, 0x100000,
                          0x100, hexmode=True)

        # Tolerance entry
        tol_f = tk.Frame(ptr_frame, bg="#212121")
        tol_f.pack(fill="x", padx=10, pady=2)
        tk.Label(tol_f, text="Tolerance: \u00b1", fg="#E0E0E0", bg="#212121",
                 font=("Helvetica",8)).pack(side="left")
        tol_ent = tk.Entry(tol_f, textvariable=self.ptr_tolerance, width=6,
                           bg="#424242", fg="#FFFFFF", font=("Helvetica",8),
                           bd=0)
        tol_ent.pack(side="left", padx=5)
        bind_wheel_number(tol_ent, self.ptr_tolerance, 0, 4096, 1)
        tk.Label(tol_f, text="bytes", fg="#B0BEC5", bg="#212121",
                 font=("Helvetica",8)).pack(side="left")

        self.btn_multi_pointer = tk.Button(ptr_frame,
                                           text="Scan Snapshot A (unverified)",
                                           command=self.multi_pointer_scan,
                                           font=("Helvetica",8,"bold"),
                                           bg="#E91E63", fg="white", relief="flat")
        self.btn_multi_pointer.pack(fill="x", padx=10, pady=4)

        # ----- Scan results list (right side) ------------------------------
        # The tools that used to sit here now live on the top bar, so the
        # results frame goes straight into the paned window again.
        res_frame = tk.LabelFrame(self.top_split, text=" Scan Results List ",
                                  font=("Helvetica",9,"bold"), bg="#212121",
                                  fg="#FF9800", bd=1)
        self.top_split.add(res_frame, minsize=260, stretch="always")

        self.label_results = tk.Label(res_frame, text="Matches Found: 0",
                                      font=("Helvetica",9,"bold"),
                                      fg="#B0BEC5", bg="#212121")
        self.label_results.pack(anchor="w", padx=10, pady=2)
        # res_body is created BEFORE the tree so the tree can be its child.
        # Packing the tree into a sibling frame with in_= is legal but leaves
        # it stacked behind that frame, which is why the list rendered blank.
        res_body = tk.Frame(res_frame, bg="#212121")
        res_body.pack(fill="both", expand=True, padx=10, pady=5)
        self.results_tree = ttk.Treeview(res_body,
                                         columns=("address","current","previous"),
                                         show="headings", height=5)
        self.results_tree.heading("address", text="Address")
        self.results_tree.heading("current", text="Current Value")
        self.results_tree.heading("previous", text="Previous Value")
        self.results_tree.column("address", width=100, anchor="center")
        self.results_tree.column("current", width=120, anchor="center")
        self.results_tree.column("previous", width=120, anchor="center")
        style = ttk.Style()
        style.configure("Treeview", background="#151515",
                        foreground="#4CAF50", fieldbackground="#151515",
                        font=("Courier",9,"bold"))
        style.map("Treeview", background=[("selected","#333333")])
        # The scrollbar represents the WHOLE result set, not the handful of
        # rows the Treeview holds. Inserting a million rows is what made this
        # unusable, so the tree keeps only a screenful and the scrollbar moves
        # a window over engine.scan_results instead.
        self.results_tree.pack(side="left", fill="both", expand=True)
        self.results_scroll = ttk.Scrollbar(res_body, orient="vertical",
                                            command=self._results_scroll)
        self.results_scroll.pack(side="right", fill="y")
        self._result_top = 0
        # Selection is tracked by RESULT INDEX, not by Treeview item. The tree
        # holds a fixed screenful of rows whose values are rewritten as the
        # window moves, so a selection held by item follows the screen row and
        # ends up highlighting a different address after every scroll.
        self._sel_idx = set()
        self._sel_anchor = None
        self._row_index = []             # screen row -> result index
        self.results_tree.configure(selectmode="none")
        self.results_tree.bind("<Double-Button-1>", self._add_result_to_table)
        self.results_tree.bind("<Button-1>", self._results_click)
        self.results_tree.bind("<Shift-Button-1>",
                               lambda e: self._results_click(e, "shift"))
        self.results_tree.bind("<Control-Button-1>",
                               lambda e: self._results_click(e, "ctrl"))
        self.results_tree.bind("<Button-3>", self._results_right_click)
        self.results_tree.bind("<Return>", self._add_result_to_table)
        self.results_tree.bind("<KP_Enter>", self._add_result_to_table)
        self.results_tree.bind("<Up>", lambda e: self._results_move(-1))
        self.results_tree.bind("<Down>", lambda e: self._results_move(1))
        self.results_tree.bind("<Shift-Up>",
                               lambda e: self._results_move(-1, extend=True))
        self.results_tree.bind("<Shift-Down>",
                               lambda e: self._results_move(1, extend=True))
        self.results_tree.bind("<Control-a>", self._results_select_all)
        self.results_tree.bind("<Configure>",
                               lambda e: self._render_results_window())
        # One row per wheel notch. Three was inherited from the generic helper
        # and makes a list you are reading a value in unusable.
        bind_wheel(self.results_tree,
                   lambda d: self._results_scroll("scroll", d, "units"))
        for seq, delta in (("<Prior>", -1), ("<Next>", 1)):
            self.results_tree.bind(
                seq, lambda e, d=delta: self._results_scroll(
                    "scroll", d, "pages") or "break")
        self.results_tree.bind("<Home>",
                               lambda e: self._results_scroll("moveto", 0.0))
        self.results_tree.bind("<End>",
                               lambda e: self._results_scroll("moveto", 1.0))

        # ----- Address table (bottom) --------------------------------------
        # A container in the paned window holds the table's own controls above
        # the table itself. They used to be packed onto the root window BELOW
        # the paned window, which put settings for the address table at the
        # far bottom of the screen, nowhere near what they affect.
        table_container = tk.Frame(self.main_split, bg="#212121")
        self.main_split.add(table_container, minsize=140, stretch="always")

        ref_frame = tk.Frame(table_container, bg="#212121")
        ref_frame.pack(fill="x", padx=10, pady=(4,2))
        tk.Label(ref_frame, text="Table Refresh Rate (ms):", fg="#E0E0E0",
                 bg="#212121", font=("Helvetica",9)).pack(side="left")
        self.table_refresh_interval = tk.IntVar(value=500)
        self.entry_refresh = tk.Entry(ref_frame,
                                      textvariable=self.table_refresh_interval,
                                      width=6, font=("Helvetica",9),
                                      bg="#424242", fg="#FFFFFF",
                                      insertbackground="white", bd=1)
        self.entry_refresh.pack(side="left", padx=5)
        tk.Button(ref_frame, text="Apply",
                  command=lambda: self.table_refresh_interval.set(
                      int(self.entry_refresh.get())
                      if self.entry_refresh.get().isdigit() else 500),
                  font=("Helvetica",8,"bold"), bg="#FF9800",
                  fg="#000000", relief="flat").pack(side="left", padx=5)

        tk.Label(ref_frame, text="Sort by:", fg="#E0E0E0", bg="#212121",
                 font=("Helvetica",9)).pack(side="left", padx=(15,2))
        self.sort_mode = tk.StringVar(value="Address")
        sort_menu = tk.OptionMenu(ref_frame, self.sort_mode,
                                  "Address", "Description",
                                  command=lambda _: self._on_sort_changed())
        sort_menu.config(font=("Helvetica",9), bg="#424242", fg="#E0E0E0",
                         highlightthickness=0, bd=0, activebackground="#616161")
        sort_menu.pack(side="left", padx=2)
        self.hex_display_var = tk.BooleanVar(value=False)
        tk.Checkbutton(ref_frame, text="Hex", variable=self.hex_display_var,
                       bg="#212121", fg="#E0E0E0", selectcolor="#424242",
                       activebackground="#212121", activeforeground="#E0E0E0",
                       font=("Helvetica",9),
                       command=self._on_hex_display_toggle).pack(
                           side="left", padx=(15,2))

        table_frame = tk.LabelFrame(table_container, text=" Address Table ",
                                    font=("Helvetica",9,"bold"), bg="#212121",
                                    fg="#FF9800", bd=1)
        table_frame.pack(fill="both", expand=True)

        def _restore_sashes():
            try:
                if self._saved_main_sash:
                    self.main_split.sash_place(0, 0, self._saved_main_sash)
                if self._saved_top_sash:
                    self.top_split.sash_place(0, self._saved_top_sash, 0)
            except Exception:
                pass
        self.after(200, _restore_sashes)
        header_frame = tk.Frame(table_frame, bg="#212121")
        header_frame.pack(fill="x", side="top", padx=2, pady=2)
        for i, txt in enumerate(["Freeze","Xbox Guest Offset / Pointer",
                                 "Description / Cheat Name","Type","Value"]):
            header_frame.grid_columnconfigure(i, weight=[1,5,4,2,2][i],
                                              uniform="table_cols")
            tk.Label(header_frame, text=txt, font=("Helvetica",9,"bold"),
                     fg="#FF9800", bg="#212121", anchor="center").grid(
                         row=0, column=i, sticky="ew", padx=2, pady=4)

        canvas_cont = tk.Frame(table_frame, bg="#151515")
        canvas_cont.pack(fill="both", expand=True, side="top", padx=2, pady=(0,2))
        # takefocus so the canvas can actually accept focus when a click on
        # empty space moves it off an Entry; without it focus would stay put
        # and the caret would keep blinking in the field.
        self.table_canvas = tk.Canvas(canvas_cont, bg="#151515", bd=0,
                                      highlightthickness=0, takefocus=1)
        self.table_scrollbar = tk.Scrollbar(canvas_cont, orient="vertical",
                                            command=self.table_canvas.yview)
        self.scrollable_inner = tk.Frame(self.table_canvas, bg="#151515")
        self.scrollable_window = self.table_canvas.create_window(
            (0,0), window=self.scrollable_inner, anchor="nw")
        self.table_canvas.configure(yscrollcommand=self.table_scrollbar.set)
        self.table_canvas.pack(side="left", fill="both", expand=True)
        self.table_scrollbar.pack(side="right", fill="y")
        # Clicking the empty area below the rows deselects. Tk delivers a click
        # to the widget under the pointer only - it does not bubble to parents
        # - so these fire exactly when the click missed every row.
        for w in (self.table_canvas, self.scrollable_inner):
            w.bind("<Button-1>", self._clear_table_selection)
        for c in range(5):
            self.scrollable_inner.grid_columnconfigure(
                c, weight=[1,5,4,2,2][c], uniform="table_cols")
        self.table_canvas.bind('<Configure>',
            lambda e: self.table_canvas.itemconfig(self.scrollable_window,
                                                   width=e.width))
        self.scrollable_inner.bind("<Configure>",
            lambda e: self.table_canvas.configure(
                scrollregion=self.table_canvas.bbox("all")))
        def scroll(event):
            if (event.num==4 or event.delta>0) and \
               self.table_canvas.yview()[0] <= 0:
                return "break"
            self.table_canvas.yview_scroll(
                -1 if (event.num==4 or event.delta>0) else 1, "units")
        for w in (self.table_canvas, self.scrollable_inner):
            w.bind("<MouseWheel>", scroll)
            w.bind("<Button-4>", scroll)
            w.bind("<Button-5>", scroll)
        # The rows sit ON TOP of the canvas, so with only the two bindings
        # above the wheel did nothing unless the pointer was over the
        # scrollbar or a sliver of bare canvas. Every row widget needs it too;
        # _bind_table_wheel is re-run whenever the table is rebuilt.
        self._table_scroll = scroll
        # bind_all() ran IN ADDITION to Entry's own class binding for
        # <<Paste>>, so every Ctrl+V inserted the clipboard twice - and
        # returning "break" could not prevent it, because the "all" bindtag is
        # reached only after the class binding has already pasted. The fix
        # replaces the class binding instead of layering on top of it.
        install_clipboard_fix(self)
        install_global_wheel(self)
        # Table-level copy/paste. install_clipboard_fix owns Ctrl+C/V inside
        # Entry and Text widgets and breaks out of them, so these only fire
        # when focus is not in a field being typed into.
        self.bind("<Control-c>", self._on_table_copy)
        self.bind("<Control-C>", self._on_table_copy)
        self.bind("<Control-v>", self._on_table_paste)
        self.bind("<Control-V>", self._on_table_paste)
        self.bind("<Control-a>", self._select_all_entries)
        self.bind("<Control-A>", self._select_all_entries)
        self.ui_row_widgets = {}

    # ---- Hover helpers ---------------------------------------------------
    def _apply_hover(self, btn, orig, hover):
        """Add mouse‑enter/leave hover effect to a button."""
        btn.bind("<Enter>", lambda e: btn.config(bg=hover))
        btn.bind("<Leave>", lambda e: btn.config(bg=orig))

    def _apply_hover_to_all_buttons(self):
        """Apply hover effects to all main buttons."""
        buttons = [
            (self.btn_new,        "#f44336","#ff7961"),
            (self.btn_first,      "#4CAF50","#81c784"),
            (self.btn_next,       "#2196F3","#64b5f6"),
            (self.btn_mem_view,   "#607D8B","#90a4ae"),
            (self.btn_save,       "#795548","#a1887f"),
            (self.btn_load,       "#009688","#4db6ac"),
            (self.btn_add_manual, "#9C27B0","#ce93d8"),
            (self.btn_stage1,     "#E91E63","#f06292"),
            (self.btn_stage2,     "#9C27B0","#ce93d8"),
            (self.btn_save_ptr,   "#455A64","#78909c"),
            (self.btn_load_ptr,   "#00796B","#4db6ac"),
            (self.btn_compare,    "#8BC34A","#aed581"),
            (self.btn_multi_pointer, "#E91E63","#f06292"),
        ]
        for btn, orig, hover in buttons:
            self._apply_hover(btn, orig, hover)

    # ---- Engine connection ------------------------------------------------
    def initialize_engine(self):
        """Connect to Xemu and start the freeze trainer thread."""
        if self.engine.find_xemu_base():
            self._status_connected()
            self._enable_buttons()
            self.engine.start_trainer()
        else:
            self.label_status.config(text="Waiting for Xemu...", fg="#FF9800")
        self.after(2000, self._check_connection)

    def _status_connected(self):
        """Update status bar with detected Xbox type and RAM size."""
        mb = self.engine.xbox_ram_size_mb
        machine = ("Retail" if mb == 64 else
                   "Debug / Dev Kit" if mb == 128 else
                   "Chihiro / Arcade" if mb == 256 else "Custom")
        self.label_status.config(
            text=f"Attached! Xbox {machine} ({mb}MB RAM) | PID: {self.engine.pid}",
            fg="#4CAF50")

    def _enable_buttons(self):
        """Enable all buttons once Xemu is found."""
        for btn in (self.btn_new, self.btn_first, self.btn_next,
                    self.btn_mem_view, self.btn_disasm, self.btn_save, self.btn_load,
                    self.btn_add_manual, self.btn_stage1, self.btn_stage2,
                    self.btn_multi_pointer, self.btn_dump_ram,
                    self.btn_ptr_wizard, self.btn_add_pointer,
                    self.btn_patches):
            btn.config(state="normal")

    def _disable_buttons(self):
        """Disable all buttons when Xemu is not found."""
        for btn in (self.btn_new, self.btn_first, self.btn_next,
                    self.btn_mem_view, self.btn_disasm, self.btn_save, self.btn_load,
                    self.btn_add_manual, self.btn_stage1, self.btn_stage2,
                    self.btn_multi_pointer, self.btn_dump_ram,
                    self.btn_ptr_wizard, self.btn_add_pointer,
                    self.btn_patches):
            btn.config(state="disabled")

    def _check_connection(self):
        """Periodically check if Xemu is still alive; reconnect if needed."""
        if getattr(self, '_shutting_down', False):
            return
        if getattr(self.engine, 'unsupported', False):
            self._disable_buttons()
            self.label_status.config(
                text=f"{self.engine.os_type} is not supported", fg="#f44336")
            self._conn_after_id = self.after(5000, self._check_connection)
            return
        if self.engine.pid and self.engine.is_process_alive() \
                and self.engine.xbox_ram_base is not None:
            self._conn_after_id = self.after(2000, self._check_connection)
            return
        self.engine.running = False   # retire the old thread before rebasing
        if self.engine.reconnect():
            self._status_connected()
            self._enable_buttons()
            self.engine.start_trainer()
        else:
            self._disable_buttons()
            self.label_status.config(text="Waiting for Xemu...", fg="#FF9800")
        self._conn_after_id = self.after(2000, self._check_connection)

    # _clipboard_paste() lived here. Besides pasting twice it had its
    # selection handling inverted - selection_present() true wiped the WHOLE
    # field via delete(0, END), while the else branch called
    # delete("sel.first", "sel.last") with no selection and threw. Paste is now
    # handled by install_clipboard_fix().

    # ---- Scanning logic --------------------------------------------------
    def _begin_scan(self):
        """
        Claim the scanner. False means one is already running.

        Nothing used to stop a second Next Scan from starting while the first
        was still going: each click spawned another daemon thread, and they all
        read RAM and mutated engine.scan_results and _last_full_dump at the
        same time. Rapid clicking therefore stacked up full-RAM passes that
        fought each other, and every one that finished redrew the results tree.
        New Scan appeared to fix it only because it reset the state the pileup
        had corrupted.

        _scan_in_progress is the flag _live_update_results already checks - it
        was read but never assigned anywhere, so the 100 ms live refresh was
        also reading /proc/pid/mem straight through every scan.
        """
        if getattr(self, '_scan_in_progress', False):
            return False
        self._scan_in_progress = True
        for b in (self.btn_first, self.btn_next):
            try: b.config(state="disabled")
            except Exception: pass
        self.label_status.config(text="Scanning...", fg="#FF9800")
        self.update_idletasks()
        return True

    def _end_scan(self):
        self._scan_in_progress = False
        for b in (self.btn_first, self.btn_next):
            try: b.config(state="normal")
            except Exception: pass

    def new_scan(self):
        """Reset the scan engine and clear results."""
        # Never reset underneath a running scan; that is the corruption path.
        if getattr(self, '_scan_in_progress', False):
            return
        self.engine.reset_scan_engine()
        self.results_tree.delete(*self.results_tree.get_children())
        self.label_results.config(text="Matches Found: 0", fg="#B0BEC5")

    def first_scan(self):
        """Perform the first scan with the currently entered value (threaded)."""
        val = self.entry_value.get().strip()
        vtype = self.dropdown_type_var.get()
        mode = self.dropdown_mode_var.get()
        if mode == "Between":
            low = val
            high = self.entry_value_max.get().strip()
            if self.scan_hex_mode_var.get():
                try:
                    low = str(int(low.lower().replace("0x","").replace(" ",""), 16))
                    high = str(int(high.lower().replace("0x","").replace(" ",""), 16))
                except:
                    messagebox.showerror("Error","Invalid Hex values")
                    return
            val = f"{low} {high}"
        if mode == "Unknown Value Search":
            is_unknown = True
            target = None
        else:
            if not val: return
            if mode != "Between" and self.scan_hex_mode_var.get():
                try:
                    val = str(int(val.lower().replace("0x","").replace(" ",""), 16))
                except:
                    messagebox.showerror("Error","Invalid Hex")
                    return
            is_unknown = False
            target = val

        if not self._begin_scan():
            return

        def scan_thread():
            cnt = 0
            try:
                cnt = self.engine.execute_first_scan_logic(
                    target, vtype, is_unknown=is_unknown)
            except Exception as e:
                print(f"[!] First Scan failed: {e}")
            finally:
                self.after(0, lambda c=cnt: self._first_scan_done(c, vtype))
        threading.Thread(target=scan_thread, daemon=True).start()

    def _first_scan_done(self, cnt, vtype):
        """Called from the main thread after the first scan finishes."""
        self._end_scan()
        self.label_status.config(text=f"Attached! PID:{self.engine.pid}", fg="#4CAF50")
        if self.dropdown_mode_var.get() == "Unknown Value Search":
            self.label_results.config(text=f"Unknown Snapshot Anchored: {cnt:,} spots", fg="#9C27B0")
        else:
            self.label_results.config(text=f"Matches Found: {cnt:,}", fg="#4CAF50" if cnt>0 else "#F44336")
        self._populate_results()

    def next_scan(self):
        """Filter the previous scan results with the new value/mode (threaded)."""
        val = self.entry_value.get().strip()
        vtype = self.dropdown_type_var.get()
        mode = self.dropdown_mode_var.get()
        if mode == "Between":
            low = val
            high = self.entry_value_max.get().strip()
            if self.scan_hex_mode_var.get():
                try:
                    low = str(int(low.lower().replace("0x","").replace(" ",""), 16))
                    high = str(int(high.lower().replace("0x","").replace(" ",""), 16))
                except:
                    messagebox.showerror("Error","Invalid Hex")
                    return
            val = f"{low} {high}"
        elif val and self.scan_hex_mode_var.get():
            try:
                val = str(int(val.lower().replace("0x","").replace(" ",""), 16))
            except:
                messagebox.showerror("Error","Invalid Hex")
                return
        if not self._begin_scan():
            return
        def scan_thread():
            cnt = 0
            try:
                cnt = self.engine.execute_next_scan_logic(val, vtype, mode)
            except Exception as e:
                print(f"[!] Next Scan failed: {e}")
            finally:
                # after(0) so the flag is cleared on the GUI thread; without
                # the finally, one failed scan would leave the buttons dead.
                self.after(0, lambda c=cnt: self._next_scan_done(c))
        threading.Thread(target=scan_thread, daemon=True).start()

    def _next_scan_done(self, cnt):
        self._end_scan()
        self.label_status.config(text=f"Attached! PID:{self.engine.pid}", fg="#4CAF50")
        self.label_results.config(text=f"Matches Found: {cnt:,}", fg="#2196F3" if cnt>0 else "#F44336")
        self._populate_results()

    # Upper bound on rows held by the Treeview at once. The list is now
    # virtual - the tree only ever holds what fits on screen - so this is just
    # a sanity cap for a very tall window, not a limit on what is reachable.
    RESULT_ROWS = 250

    def _visible_result_rows(self):
        """How many rows actually fit in the results pane right now."""
        try:
            h = self.results_tree.winfo_height()
            rh = ttk.Style().lookup("Treeview", "rowheight")
            rh = int(rh) if rh else 20
        except Exception:
            h, rh = 0, 20
        # Subtract the column-heading strip, which is roughly one row tall.
        # Without it the window is one row too big and the bottom entry is
        # drawn clipped - unreadable, and unreachable by scrolling since it is
        # already "shown".
        return max(1, min(self.RESULT_ROWS, ((h - rh) // max(1, rh)) or 1))

    # ---- results selection ----------------------------------------------
    def _result_row_index(self, event):
        """Result index under the pointer, or None."""
        item = self.results_tree.identify_row(event.y)
        if not item:
            return None
        try:
            row = list(self.results_tree.get_children()).index(item)
        except ValueError:
            return None
        return self._row_index[row] if row < len(self._row_index) else None

    def _results_click(self, event, mode=None):
        """
        Click handling, done by hand.

        Tk's own extended selectmode selects Treeview items, which is the wrong
        unit here - and it cannot express "shift-click something that has been
        scrolled past", because the anchor row no longer exists in the tree. So
        selection is kept as a set of result indices and the tree is told what
        to highlight after each render.
        """
        self.results_tree.focus_set()
        idx = self._result_row_index(event)
        if idx is None:
            return "break"
        if mode == "ctrl":
            self._sel_idx.symmetric_difference_update({idx})
            self._sel_anchor = idx
        elif mode == "shift" and self._sel_anchor is not None:
            lo, hi = sorted((self._sel_anchor, idx))
            self._sel_idx = set(range(lo, hi + 1))
        else:
            self._sel_idx = {idx}
            self._sel_anchor = idx
        self._apply_result_selection()
        self._update_result_selection_label()
        return "break"

    def _results_move(self, step, extend=False):
        """Arrow-key selection, scrolling the window only when it has to."""
        total = len(self.engine.scan_results)
        if not total:
            return "break"
        cur = self._sel_anchor if self._sel_anchor is not None else \
            self._result_top
        nxt = max(0, min(total - 1, cur + step))
        rows = self._visible_result_rows()
        if extend and self._sel_idx:
            self._sel_idx.add(nxt)
        else:
            self._sel_idx = {nxt}
        self._sel_anchor = nxt
        if nxt < self._result_top:
            self._result_top = nxt
        elif nxt >= self._result_top + rows:
            self._result_top = nxt - rows + 1
        self._render_results_window()
        self._update_result_selection_label()
        return "break"

    def _results_select_all(self, event=None):
        self._sel_idx = set(range(len(self.engine.scan_results)))
        self._sel_anchor = 0
        self._apply_result_selection()
        self._update_result_selection_label()
        return "break"

    def _apply_result_selection(self):
        """Highlight the visible rows whose result index is selected."""
        items = list(self.results_tree.get_children())
        want = [it for it, gi in zip(items, self._row_index)
                if gi in self._sel_idx]
        self.results_tree.selection_set(want)

    def _update_result_selection_label(self):
        n = len(self._sel_idx)
        total = len(self.engine.scan_results)
        base = f"Matches Found: {total}"
        self.label_results.config(
            text=base + (f"   |   {n} selected" if n > 1 else ""))

    def _selected_result_offsets(self):
        """Physical offsets for the current selection, in list order."""
        res = self.engine.scan_results
        return [res[i] for i in sorted(self._sel_idx) if 0 <= i < len(res)]

    def _results_scroll(self, *args):
        """
        Scrollbar / wheel / page-key handler.

        Moves the window over engine.scan_results rather than scrolling the
        Treeview, so the cost of a scroll is one screenful of reads no matter
        how many million matches there are.
        """
        total = len(self.engine.scan_results)
        rows = self._visible_result_rows()
        span = max(0, total - rows)
        if not args:
            return
        if args[0] == "moveto":
            self._result_top = int(round(float(args[1]) * span))
        elif args[0] == "scroll":
            step = int(args[1])
            unit = args[2] if len(args) > 2 else "units"
            self._result_top += step * (rows if unit == "pages" else 1)
        self._result_top = max(0, min(span, self._result_top))
        self._render_results_window()
        return "break"

    def _render_results_window(self):
        """Redraw the visible slice, reusing rows instead of rebuilding them."""
        total = len(self.engine.scan_results)
        rows = self._visible_result_rows()
        span = max(0, total - rows)
        self._result_top = max(0, min(span, getattr(self, '_result_top', 0)))
        if total:
            lo = self._result_top / total
            hi = min(1.0, (self._result_top + rows) / total)
        else:
            lo, hi = 0.0, 1.0
        try:
            self.results_scroll.set(lo, hi)
        except Exception:
            pass

        offs = self.engine.scan_results[self._result_top:self._result_top + rows]
        self._row_index = list(range(self._result_top,
                                     self._result_top + len(offs)))
        values = self._format_result_rows(offs)
        items = list(self.results_tree.get_children())
        # Reuse existing rows; only add or trim when the pane is resized.
        while len(items) < len(values):
            items.append(self.results_tree.insert("", "end", values=("", "", "")))
        for extra in items[len(values):]:
            self.results_tree.delete(extra)
        items = items[:len(values)]
        for item, v in zip(items, values):
            if tuple(self.results_tree.item(item, "values")) != v:
                self.results_tree.item(item, values=v)
        # The rows just changed meaning, so the highlight has to be reapplied
        # against what they mean now.
        self._apply_result_selection()

    def _format_result_rows(self, offs):
        """Read and format one screenful of results."""
        vtype = self.dropdown_type_var.get()
        fmt, size = self.engine._get_type_params(vtype, "0")
        hex_mode = self.scan_hex_mode_var.get()
        try:
            mem = open(f"/proc/{self.engine.pid}/mem", "rb") \
                  if self.engine.os_type == "Linux" else None
        except Exception:
            mem = None
        out = []
        for off in offs:
            raw = self.engine.read_mem(self.engine.xbox_ram_base + off, size, mem)
            if hex_mode and fmt not in ("string", "bytes"):
                if "float" in vtype:
                    cur = raw.hex().upper()
                else:
                    try:
                        val, = struct.unpack(fmt, raw)
                        cur = f"0x{val:X}"
                    except Exception:
                        cur = "?"
            else:
                cur = self.engine.format_value(raw, vtype)
            prev = self.engine.scan_values.get(off, "?")
            if hex_mode and fmt not in ("string", "bytes", "float"):
                try:
                    prev = f"0x{int(prev):X}"
                except Exception:
                    pass
            shown = self.engine.to_display_addr(off)
            out.append((f"0x{shown:08X}", cur, prev))
        if mem:
            mem.close()
        return out

    def _populate_results(self):
        """Show a fresh result set from the top."""
        self._result_top = 0
        self._sel_idx.clear()
        self._sel_anchor = None
        self._render_results_window()
        total = len(self.engine.scan_results)
        self.label_results.config(
            text=f"Matches Found: {total:,}",
            fg="#2196F3" if total else "#F44336")
        if self.engine.scan_results:
            self._live_update_results()

    def _live_update_results(self):
        """Refresh the visible slice, then reschedule."""
        if not self.engine.scan_results: return
        if getattr(self, '_scan_in_progress', False): return
        self._render_results_window()
        self.after(self.table_refresh_interval.get(), self._live_update_results)

    def _on_hex_toggle(self):
        """Rebuild results when HEX checkbox is toggled."""
        if self.engine.scan_results: self._populate_results()

    # ---- Address table helpers -------------------------------------------
    def _add_result_to_table(self, event=None):
        """
        Add the selected scan result(s) to the address table.

        Bound to double-click and to Enter, and shared with the right-click
        menu, so a selection built by shift-clicking across a scroll adds in one
        go. Offsets already in the table are skipped rather than duplicated.
        """
        offs = self._selected_result_offsets()
        if not offs:
            return "break"
        vtype = self.dropdown_type_var.get()
        have = {e[0] for e in self.engine.address_table}
        added = 0
        for off in offs:
            if off in have:
                continue
            have.add(off)
            self.engine.address_table.append([
                off, "No Description", vtype,
                False, "0", False, 0, [], off, "",
                self.engine._next_entry_id])
            self.engine._next_entry_id += 1
            added += 1
        self._rebuild_table = True
        self.update_table_view()
        skipped = len(offs) - added
        msg = f"Added {added} address(es) to the table"
        if skipped:
            msg += f"; {skipped} already there"
        self.label_results.config(text=msg)
        self.after(2500, self._update_result_selection_label)
        return "break"

    def _results_right_click(self, event):
        """Right-click a result: browse it, or add the whole selection."""
        idx = self._result_row_index(event)
        # Right-clicking outside the selection moves it, the way every list
        # does; right-clicking inside one keeps it, so a multi-selection is not
        # thrown away by the click that opens the menu for it.
        if idx is not None and idx not in self._sel_idx:
            self._sel_idx = {idx}
            self._sel_anchor = idx
            self._apply_result_selection()
            self._update_result_selection_label()
        offs = self._selected_result_offsets()
        if not offs:
            return
        menu = tk.Menu(self, tearoff=0)
        n = len(offs)
        if n == 1:
            shown = self.engine.to_display_addr(offs[0])
            menu.add_command(label="Add Address to Address Table",
                             command=self._add_result_to_table)
            menu.add_command(label=f"Browse 0x{shown:08X}",
                             command=lambda a=shown: self.open_mem_viewer(a))
        else:
            menu.add_command(
                label=f"Add Selected Addresses to Address Table ({n})",
                command=self._add_result_to_table)
            menu.add_separator()
            menu.add_command(label="Select All Results",
                             command=self._results_select_all)
        popup_menu(menu, event.x_root, event.y_root)

    def add_manual(self):
        """Add an address manually typed by the user."""
        try:
            raw = self.entry_manual_addr.get().strip()
            clean = re.sub(r'[^0-9a-f]','', raw.lower().replace("0x","").replace(" ",""))
            if not clean: raise ValueError
            off = int(clean, 16)
            maxb = self.engine.xbox_ram_size_mb * 1024 * 1024
            if not (0 <= off < maxb): raise ValueError
            self.engine.address_table.append([
                off, "Manual Record", self.dropdown_type_var.get(),
                False, "0", False, 0, [], off, "", self.engine._next_entry_id])
            self.engine._next_entry_id += 1
            self.entry_manual_addr.delete(0, tk.END)
            self.entry_manual_addr.insert(0, f"0x{off:08X}")
            self._rebuild_table = True
            self.update_table_view()
            self.entry_manual_addr.config(bg="#A5D6A7")
            self.after(200, lambda: self.entry_manual_addr.config(bg="#424242"))
        except: messagebox.showerror("Error","Invalid address.")

    # ---- Table persistence ------------------------------------------------
    def save_table(self):
        """Save the current address table to a JSON file."""
        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                            filetypes=[("Xemu Cheat Tables","*.txt")])
        if not path: return
        try:
            # 11 fields: the 10 originals plus is_virtual. The entry id is
            # regenerated on load, so it is deliberately not saved.
            out = []
            for e in self.engine.address_table:
                row = list(e[:10])
                while len(row) < 10:
                    row.append("")
                row.append(bool(e[11]) if len(e) > 11 else bool(e[5]))
                out.append(row)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(out, f, indent=4, ensure_ascii=False)
            # Ownership handback now lives in xemu_privs so that every write
            # site gets it, not just this one, and so that a root shell with
            # no SUDO_USER set is still handled.
            xemu_privs.reclaim(path)
            messagebox.showinfo("Saved", "Table saved.")
        except Exception as e: messagebox.showerror("Error", str(e))

    def load_table(self):
        """Load an address table from a JSON file."""
        path = filedialog.askopenfilename(filetypes=[("Xemu Cheat Tables","*.txt")])
        if not path: return
        try:
            with open(path, "r", encoding="utf-8") as f: data = json.load(f)
            self.engine.address_table.clear()
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, list):
                        virt = None
                        if len(item) > 10:
                            virt = bool(item[10])       # saved is_virtual
                            item = item[:10]
                        while len(item) < 10: item.append("")
                        item.append(self.engine._next_entry_id)
                        item.append(bool(item[5]) if virt is None else virt)
                        self.engine._next_entry_id += 1
                        self.engine.address_table.append(item)
            else:  # old dict format
                for k, v in data.items():
                    off = int(k, 16)
                    if isinstance(v, list):
                        entry = [off]
                        defaults = ["No Description","int8",False,"0",False,0,[],off,""]
                        for i in range(9):
                            entry.append(v[i] if i < len(v) else defaults[i])
                        entry.append(self.engine._next_entry_id)
                        self.engine._next_entry_id += 1
                        self.engine.address_table.append(entry)
            self.groups = sorted({e[9] for e in self.engine.address_table if e[9]})
            self.collapsed_groups.clear()
            self._rebuild_table = True
            self.update_table_view()
        except Exception as e: messagebox.showerror("Error", str(e))

    # ---- Pointer definition modal -----------------------------------------
    def _ptr_modal(self, row_offset):
        """
        Open a dialog to configure a pointer entry:
        base offset and space‑separated offsets.
        """
        entry = None
        for e in self.engine.address_table:
            if e[0] == row_offset: entry = e; break
        if not entry: return
        win = tk.Toplevel(self)
        win.title("Pointer Configuration")
        win.geometry("460x340")
        win.configure(bg="#212121")
        is_ptr_var = tk.BooleanVar(value=entry[5])
        tk.Checkbutton(win, text="Is this entry a Pointer?",
                       variable=is_ptr_var, font=("Helvetica",9,"bold"),
                       fg="#FF9800", bg="#212121", selectcolor="#424242",
                       activebackground="#212121", activeforeground="#FF9800").pack(pady=10)
        bf = tk.Frame(win, bg="#212121"); bf.pack(fill="x", padx=20, pady=5)
        tk.Label(bf, text="Base Offset Address:", fg="#FFFFFF", bg="#212121").pack(side="left")
        base_ent = tk.Entry(bf, font=("Courier",10,"bold"), bg="#424242",
                            fg="#00FF00", width=14); base_ent.pack(side="left")
        base_ent.insert(0, f"0x{entry[6]:08X}" if entry[6] else f"0x{row_offset:08X}")
        tk.Label(win, text="Pointer Level Offsets (space-separated hex):",
                 fg="#FFFFFF", bg="#212121", font=("Helvetica",9)).pack(pady=5)
        off_ent = tk.Entry(win, font=("Courier",10,"bold"), bg="#424242",
                           fg="#00FF00", width=36); off_ent.pack(pady=2, padx=20)
        off_ent.insert(0, " ".join(f"{x:X}" for x in entry[7]))
        tk.Label(win, text="Example: 14 0 4", font=("Helvetica",8,"italic"),
                 fg="#B0BEC5", bg="#212121").pack()
        def save():
            try:
                b = int(base_ent.get().strip(), 16)
                o = [int(x,16) for x in off_ent.get().strip().split()] \
                    if off_ent.get().strip() else []
                entry[5] = is_ptr_var.get()
                entry[6] = b
                entry[7] = o
                win.destroy()
                self._rebuild_table = True
                self.update_table_view()
            except: messagebox.showerror("Error","Invalid hex input")
        tk.Button(win, text="Commit", command=save,
                  font=("Helvetica",9,"bold"), bg="#4CAF50", fg="white",
                  relief="flat", padx=15, pady=4).pack(pady=20)
        win.grab_set()

    # ---- Table view update ------------------------------------------------
    def _queue_table_refresh(self):
        """Schedule exactly one pending table refresh."""
        if getattr(self, '_shutting_down', False):
            return
        try:
            if getattr(self, '_table_after_id', None) is not None:
                self.after_cancel(self._table_after_id)
        except Exception:
            pass
        try:
            ms = max(16, int(self.table_refresh_interval.get()))
        except Exception:
            ms = 500
        self._table_after_id = self.after(ms, self.update_table_view)

    def update_table_view(self):
        """
        Redraw the address table (or just update live values if nothing changed).
        """
        if not hasattr(self, 'scrollable_inner'): return
        # The reschedule lives at the end of this method, so ANY exception in
        # here silently kills the refresh loop for the rest of the session -
        # the table freezes at whatever it last displayed. Guarantee the next
        # tick is queued regardless of what goes wrong.
        self._queue_table_refresh()
        # Nothing can be read once xemu exits. self.engine.pid still points at
        # the dead process and xbox_ram_base is cleared by reconnect(), so
        # every row would try None + offset and raise - a hundred times a
        # second, which is what filled the terminal with identical tracebacks.
        # The rows keep their last values until a new process is attached.
        if self.engine.pid is None or self.engine.xbox_ram_base is None:
            return
        try:
            mem = open(f"/proc/{self.engine.pid}/mem", "rb")
        except Exception:
            mem = None
        for e in self.engine.address_table:
            while len(e) < 10: e.append("")
            if len(e) < 11: e.append(self.engine._next_entry_id); \
                            self.engine._next_entry_id += 1
            if len(e) < 12: e.append(bool(e[5]))   # is_virtual, default on

        if not self._rebuild_table:
            # Fast path: only update the displayed values
            # Resolve everything first, then decide how to read it.
            #
            # A naive "cache the 4 KB page" scheme is a big win for a clustered
            # table (one pread instead of 200) and a 1000x LOSS for a scattered
            # one: 200 rows a page apart pulled 800 KB per refresh instead of
            # 800 bytes, a hundred times a second. Measured, not assumed. So a
            # page is only read whole when at least two entries want bytes from
            # it; lone entries are read exactly.
            plan = []
            page_hits = {}
            for e in self.engine.address_table:
                off = e[10]
                tgt = self.engine.resolve_entry(e, mem) if e[5] else e[8]
                if e[5] and tgt is not None:
                    e[0] = tgt
                if off not in self.ui_row_widgets or \
                        self.ui_row_editing_locks.get(off, False):
                    continue
                fmt, size = self.engine._get_type_params(e[2], "0")
                read_sz = 256 if fmt == "string" else size
                plan.append((e, off, tgt, fmt, read_sz))
                if tgt is not None and read_sz <= 0x1000 and \
                        (tgt & 0xFFF) + read_sz <= 0x1000:
                    page = tgt & ~0xFFF
                    page_hits[page] = page_hits.get(page, 0) + 1

            page_cache = {}

            def read_planned(phys, n):
                page = phys & ~0xFFF
                if page_hits.get(page, 0) < 2 or n > 0x1000 or \
                        (phys - page) + n > 0x1000:
                    return self.engine.read_mem(
                        self.engine.xbox_ram_base + phys, n, mem)
                buf = page_cache.get(page)
                if buf is None:
                    buf = self.engine.read_mem(
                        self.engine.xbox_ram_base + page, 0x1000, mem)
                    page_cache[page] = buf
                start = phys - page
                return buf[start:start + n]

            for e, off, tgt, fmt, read_sz in plan:
                # Rows are keyed by entry id, not address: a pointer's
                # resolved address changes whenever the game reallocates, so an
                # address key orphans the row and every callback bound to it.
                _, _, _, _, _, val_ent, val_var, _ = self.ui_row_widgets[off]
                cur = "Error"
                if tgt is not None:
                    raw = read_planned(tgt, read_sz)
                    try:
                        if fmt == "string":
                            null = raw.find(b'\x00')
                            if null >= 0:
                                raw = raw[:null]
                            cur = raw.decode('utf-8', 'ignore')
                        elif fmt == "bytes":
                            cur = raw.hex()
                        else:
                            val = struct.unpack(fmt, raw)[0]
                            if self.hex_display_var.get() and \
                                    fmt in ("B", "<H", "<I"):
                                w = {"B": 2, "<H": 4, "<I": 8}[fmt]
                                cur = f"{val:0{w}X}"
                            else:
                                cur = str(val)
                    except Exception:
                        pass
                # Only touch the variable when the text actually changed. set()
                # runs Tk traces and redraws the entry every time; at the
                # default 10 ms refresh that is a constant redraw of every row,
                # including the ones whose value has not moved.
                if val_var.get() != cur:
                    val_var.set(cur)

            if mem: mem.close()
            return

        # Full rebuild (layout changed)
        for off in list(self.ui_row_widgets.keys()):
            if not any(e[0] == off for e in self.engine.address_table):
                for w in self.ui_row_widgets[off]:
                    if isinstance(w, tk.Widget): w.destroy()
                del self.ui_row_widgets[off]

        ungrouped = []
        grouped = {}
        for e in self.engine.address_table:
            off, grp = e[0], e[9]
            if grp: grouped.setdefault(grp, {})[off] = e
            else: ungrouped.append((off, e))
        for child in self.scrollable_inner.winfo_children(): child.destroy()
        self.ui_row_widgets.clear()
        self._row_order = []
        # Rows that no longer exist must not stay selected: a stale id would
        # survive a delete and get picked up again by the next bulk action
        # once the id counter came back around.
        live = {e[10] for e in self.engine.address_table if len(e) > 10}
        self._selected_entry_ids &= live
        if self._selected_entry_id not in live:
            self._selected_entry_id = None
        if self._sel_anchor not in live:
            self._sel_anchor = None

        def make_group_header(name, row, expanded):
            lbl = tk.Label(self.scrollable_inner,
                           text=f"  {'▼' if expanded else '▶'}  Group: {name}",
                           font=("Helvetica",10,"bold"), bg="#2C2C2C",
                           fg="#FF9800", anchor="w", cursor="hand2")
            lbl.grid(row=row, column=0, columnspan=5, sticky="ew", padx=2, pady=(4,2))
            lbl.bind("<Button-1>", lambda e, gn=name: self._toggle_group(gn))
            menu = tk.Menu(self, tearoff=0, bg="#424242", fg="#FFFFFF",
                           activebackground="#FF9800", activeforeground="#000000")
            menu.add_command(label="Rename group",
                             command=lambda gn=name: self._rename_group(gn))
            menu.add_command(label="Delete group",
                             command=lambda gn=name: self._delete_group(gn))
            menu.add_command(label="Ungroup all",
                             command=lambda gn=name: self._ungroup_all(gn))
            lbl.bind("<Button-3>", lambda e, m=menu: popup_menu(m, e.x_root, e.y_root))
            return lbl

        def make_entry_row(eid, entry, r):
            fmt, size = self.engine._get_type_params(entry[2], "0")
            is_ptr = entry[5]
            if is_ptr:
                tgt = self.engine.resolve_entry(entry, mem)
                addr_text = ("V" if (len(entry) > 11 and entry[11]) else "P") + \
                            f"->[0x{entry[6]:06X}+" + \
                            ",".join(f"{x:X}" for x in entry[7]) + "]"
            else:
                tgt = entry[8]
                addr_text = f"0x{tgt:08X}"
            cur_val = "Error"
            if tgt is not None:
                read_sz = 256 if fmt == "string" else size
                raw = self.engine.read_mem(self.engine.xbox_ram_base + tgt,
                                           read_sz, mem)
                try:
                    if fmt == "string":
                        null = raw.find(b'\x00')
                        if null >= 0: raw = raw[:null]
                        cur_val = raw.decode('utf-8', 'ignore')
                    elif fmt == "bytes": cur_val = raw.hex()
                    else:
                        val = struct.unpack(fmt, raw)[0]
                        if self.hex_display_var.get() and fmt in ("B","<H","<I"):
                            w = {"B":2,"<H":4,"<I":8}[fmt]
                            cur_val = f"{val:0{w}X}"
                        else: cur_val = str(val)
                except: pass

            freeze_var = tk.BooleanVar(value=entry[3])
            val_var = tk.StringVar(value=cur_val)
            type_var = tk.StringVar(value=entry[2])

            chk = tk.Checkbutton(self.scrollable_inner, variable=freeze_var,
                                 bg="#151515", selectcolor="#424242",
                                 command=lambda o=eid, v=freeze_var:
                                     self._toggle_freeze(o, v.get()))
            chk.grid(row=r, column=0, sticky="nsew", padx=2, pady=2)
            if is_ptr:
                addr_ent = tk.Entry(self.scrollable_inner,
                                    font=("Courier",9,"bold"), fg="#4CAF50",
                                    bg="#151515",
                                    disabledforeground="#4CAF50", bd=0,
                                    justify='center')
                # insert() is a no-op on a disabled Entry, so fill it first and
                # disable afterwards - otherwise the cell renders blank.
                addr_ent.insert(0, addr_text)
                # 'readonly' rather than 'disabled': a disabled Tk widget
                # receives no events at all, so right-clicking a pointer row's
                # address cell produced no context menu and there was no way to
                # move a pointer entry into a group.
                addr_ent.config(state='readonly', readonlybackground="#151515")
                # A pointer row's address is computed, so it isn't editable in
                # place; double-click reopens the chain editor instead.
                addr_ent.bind("<Double-Button-1>",
                              lambda e, ent=entry: self._edit_pointer_entry(ent))
            else:
                addr_ent = tk.Entry(self.scrollable_inner,
                                    font=("Courier",9,"bold"), fg="#4CAF50",
                                    bg="#151515", insertbackground="white",
                                    bd=1, justify='center')
                addr_ent.insert(0, addr_text)
                addr_ent._orig = addr_text
                addr_ent.bind("<FocusIn>",
                              lambda e, ent=addr_ent: setattr(ent,'_orig',ent.get()))
                def commit_addr(e, o=eid, ent=addr_ent):
                    self._commit_addr_change(o, ent.get())
                addr_ent.bind("<Return>", commit_addr)
                addr_ent.bind("<KP_Enter>", commit_addr)
                addr_ent.bind("<FocusOut>", commit_addr)
            addr_ent.grid(row=r, column=1, sticky="nsew", padx=2, pady=2)
            desc_ent = tk.Entry(self.scrollable_inner, font=("Helvetica",10),
                                bg="#333333", fg="#FFFFFF", bd=1,
                                insertbackground="white")
            desc_ent.insert(0, entry[1])
            desc_ent.grid(row=r, column=2, sticky="nsew", padx=4, pady=2)
            type_menu = tk.OptionMenu(self.scrollable_inner, type_var,
                                      *self.type_options,
                                      command=lambda v, o=eid:
                                          self._on_type_change(o, v))
            type_menu.config(font=("Helvetica",9), bg="#424242", fg="#E0E0E0",
                             highlightthickness=0, bd=0, activebackground="#616161")
            type_menu.grid(row=r, column=3, sticky="nsew", padx=2, pady=2)
            type_menu._wheel_claimed = True
            bind_wheel_cycle(type_menu, list(self.type_options),
                             type_var.get,
                             lambda v, o=eid, tv=type_var: (
                                 tv.set(v), self._on_type_change(o, v)))
            val_ent = tk.Entry(self.scrollable_inner, textvariable=val_var,
                               font=("Helvetica",10,"bold"), bg="#FFFFFF",
                               fg="#000000", bd=1, insertbackground="black")
            val_ent.grid(row=r, column=4, sticky="nsew", padx=4, pady=2)

            for w, cb in ((desc_ent, lambda e, o=eid, d=desc_ent:
                               self._update_desc(o, d.get())),
                          (val_ent, lambda e, o=eid, v=val_ent:
                               self._commit_value(o, v.get()))):
                w.bind("<FocusIn>", lambda e, o=eid:
                       self.ui_row_editing_locks.__setitem__(o, True))
                w.bind("<FocusOut>", lambda e, o=eid, cb=cb:
                       (self.ui_row_editing_locks.__setitem__(o, False), cb(e)))
                w.bind("<Return>", lambda e, cb=cb: cb(e))
                w.bind("<KP_Enter>", lambda e, cb=cb: cb(e))

            popup = tk.Menu(self, tearoff=0, bg="#424242", fg="#FFFFFF",
                            activebackground="#FF9800", activeforeground="#000000")
            # Three explicit entries rather than one item with a dropdown
            # buried inside the window - this is where you look for them.
            popup.add_command(
                label="Find out what writes to this address",
                command=lambda o=eid: self._find_what_accesses(o, "writes"))
            popup.add_command(
                label="Find out what reads this address",
                command=lambda o=eid: self._find_what_accesses(o, "reads"))
            popup.add_command(
                label="Find out what accesses this address",
                command=lambda o=eid: self._find_what_accesses(o,
                                                               "reads + writes"))
            popup.add_separator()
            popup.add_command(label="Duplicate",
                              command=lambda o=eid: self._duplicate_entry(o))
            popup.add_command(label="Copy  (Ctrl+C)",
                              command=lambda o=eid: self._copy_entry(o))
            popup.add_command(label="Paste  (Ctrl+V)",
                              command=self._paste_entry,
                              state="normal" if getattr(
                                  self, '_entry_clipboard', None) else "disabled")
            popup.add_separator()
            popup.add_command(label="Remove",
                              command=lambda o=eid: self._delete_entry(o))
            if is_ptr:
                # Browse now lands on the slot holding the BASE POINTER, not on
                # the fully dereferenced target. Checking whether a chain is
                # still good means looking at the base, and the resolved
                # address was already reachable from the value column.
                is_virt = bool(entry[11]) if len(entry) > 11 else True
                base_ok = False
                try:
                    steps0 = self.engine.resolve_chain_steps(entry, mem)
                    base_ok = steps0[0]['phys'] is not None
                except Exception:
                    pass
                popup.add_command(
                    label=(f"Browse base 0x{entry[6]:08X}"
                           + ("  (virtual)" if is_virt else "")
                           if base_ok else "Browse base (unresolved)"),
                    # A virtual entry hands over the VIRTUAL address with the
                    # flag set; the viewer turns its own Virtual tickbox on.
                    command=lambda a=entry[6], v=is_virt:
                        self.open_mem_viewer(a, virtual=v),
                    state="normal" if base_ok else "disabled")

                # One entry per dereference, so each link in the chain can be
                # inspected on its own.
                lvl_menu = tk.Menu(popup, tearoff=0, bg="#424242", fg="#FFFFFF",
                                   activebackground="#FF9800",
                                   activeforeground="#000000")
                def rebuild_levels(m=None, ent=entry):
                    """Re-resolve on open: a chain moves while the game runs."""
                    lvl_menu.delete(0, "end")
                    try:
                        steps = self.engine.resolve_chain_steps(ent, None)
                    except Exception as e:
                        lvl_menu.add_command(label=f"resolve failed: {e}",
                                             state="disabled")
                        return
                    for st in steps:
                        lvl_menu.add_command(
                            label=st['label']
                                  + (f"   = 0x{st['value']:08X}"
                                     if st['value'] is not None else ""),
                            command=lambda a=st['addr'], v=st['virtual']:
                                self.open_mem_viewer(a, virtual=v)
                                if a is not None else None,
                            state="normal" if st['phys'] is not None
                                  else "disabled")
                lvl_menu.configure(postcommand=rebuild_levels)
                rebuild_levels()
                popup.add_cascade(label="Browse level", menu=lvl_menu)
            else:
                popup.add_command(
                    label=f"Browse 0x{tgt:08X}" if tgt else "Browse",
                    command=lambda o=tgt: self.open_mem_viewer(o) if o else None)
            move_menu = tk.Menu(popup, tearoff=0)
            move_menu.add_command(label="None",
                                  command=lambda o=eid: self._move_to_group(o, ""))
            if self.groups:
                move_menu.add_separator()
                for g in self.groups:
                    move_menu.add_command(label=g,
                                          command=lambda o=eid, gn=g:
                                              self._move_to_group(o, gn))
            move_menu.add_separator()
            move_menu.add_command(label="New group…",
                                  command=lambda o=eid: self._new_group(o))
            popup.add_cascade(label="Move to group", menu=move_menu)
            for w in (chk, addr_ent, desc_ent, val_ent):
                # Remember which rows are selected, so Ctrl+C and the bulk
                # actions have a target even though these are plain widgets
                # rather than a Treeview. Ctrl+click toggles one row,
                # Shift+click extends a range, a plain click replaces the
                # selection.
                w.bind("<Button-1>", lambda e, o=eid:
                       self._on_row_click(o, e), add="+")
                w.bind("<Button-3>", lambda e, o=eid, m=popup:
                       self._on_row_right_click(o, e, m), add="+")
                # Delete removes every selected row, not just the one under
                # the pointer - otherwise selecting ten rows and pressing
                # Delete would quietly drop only one of them.
                w.bind("<Delete>", lambda e, o=eid:
                       self._delete_selected_entries(o))
                w.bind("<Control-d>", lambda e, o=eid:
                       (self._duplicate_entry(o), "break")[1])
            # Shift+click needs to know what "between these two rows" means,
            # and that is screen order - which is neither entry-id order nor
            # address_table order once groups and Description sorting are in
            # play. Rows are built top to bottom, so recording them here is
            # exactly the visible order.
            self._row_order.append(eid)
            return (chk, freeze_var, desc_ent, type_menu, type_var,
                    val_ent, val_var, addr_ent)

        row = 0
        if ungrouped:
            tk.Label(self.scrollable_inner, text="  Ungrouped",
                     font=("Helvetica",9,"italic"), bg="#1E1E1E",
                     fg="#B0BEC5", anchor="w").grid(row=row, column=0,
                                                    columnspan=5, sticky="ew")
            row += 1
            sort_key = (lambda x: (x[1][1].lower(), x[0])) \
                       if self.sort_mode.get() == "Description" \
                       else (lambda x: x[0])
            for off, ent in sorted(ungrouped, key=sort_key):
                self.ui_row_widgets[ent[10]] = make_entry_row(ent[10], ent, row)
                row += 1
        for gname in self.groups:
            if gname in grouped:
                expanded = not self.collapsed_groups.get(gname, False)
                make_group_header(gname, row, expanded)
                row += 1
                if expanded:
                    sort_key = (lambda x: (x[1][1].lower(), x[0])) \
                               if self.sort_mode.get() == "Description" \
                               else (lambda x: x[0])
                    for off, ent in sorted(grouped[gname].items(), key=sort_key):
                        self.ui_row_widgets[ent[10]] = make_entry_row(ent[10], ent, row)
                        row += 1
        for gname in grouped:
            if gname not in self.groups:
                expanded = not self.collapsed_groups.get(gname, False)
                make_group_header(gname, row, expanded)
                row += 1
                if expanded:
                    sort_key = (lambda x: (x[1][1].lower(), x[0])) \
                               if self.sort_mode.get() == "Description" \
                               else (lambda x: x[0])
                    for off, ent in sorted(grouped[gname].items(), key=sort_key):
                        self.ui_row_widgets[ent[10]] = make_entry_row(ent[10], ent, row)
                        row += 1
        self.scrollable_inner.update_idletasks()
        self.table_canvas.configure(scrollregion=self.table_canvas.bbox("all"))
        # Rows are new widgets every rebuild, and each one covers the canvas
        # underneath, so the wheel bindings have to be reapplied here or the
        # pointer only scrolls while over the scrollbar.
        self._bind_table_wheel()
        # Rows are brand new widgets after a rebuild and come back with default
        # colours, so the selection has to be repainted or it looks like the
        # table cleared it (e.g. after a type change or a group move).
        self._apply_row_highlight()
        if mem: mem.close()
        self._rebuild_table = False

    def _bind_table_wheel(self):
        """Give every widget in the address table the pane's wheel handler."""
        scroll = getattr(self, '_table_scroll', None)
        if scroll is None:
            return
        def walk(w):
            # A type OptionMenu already cycles code types on the wheel; leave
            # those alone rather than stealing the event back for scrolling.
            if not getattr(w, '_wheel_claimed', False):
                for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
                    try: w.bind(seq, scroll)
                    except Exception: pass
            for c in w.winfo_children():
                walk(c)
        walk(self.scrollable_inner)

    # ---- Inline edit helpers ----------------------------------------------
    def _entry_by_id(self, eid):
        """
        Look up a table entry by its stable id.

        Rows used to be identified by address, which breaks for pointers: their
        resolved address changes whenever the game reallocates, so a callback
        capturing the old address silently matched nothing and the edit was
        dropped. entry[10] never changes.
        """
        for e in self.engine.address_table:
            if len(e) > 10 and e[10] == eid:
                return e
        return None

    def _on_type_change(self, eid, new_type):
        """Called when the user changes the type of a table entry."""
        e = self._entry_by_id(eid)
        if e is not None: e[2] = new_type
        self._rebuild_table = True
        self.update_table_view()

    def _toggle_freeze(self, eid, checked):
        """Enable/disable freezing for a table entry."""
        e = self._entry_by_id(eid)
        if e is not None:
            e[3] = checked
            if checked and eid in self.ui_row_widgets:
                e[4] = self.ui_row_widgets[eid][5].get().strip()

    def _update_desc(self, eid, txt):
        """Update the description of a table entry."""
        e = self._entry_by_id(eid)
        if e is not None: e[1] = txt

    def _commit_value(self, eid, txt):
        """Write a new value directly to the Xbox RAM."""
        e = self._entry_by_id(eid)
        if e is None: return
        packed = self.engine.pack_freeze_data(txt, e[2])
        if packed:
            try:
                mem = open(f"/proc/{self.engine.pid}/mem", "rb+") \
                      if self.engine.os_type == "Linux" else None
            except Exception:
                mem = None
            tgt = self.engine.resolve_entry(e, mem)
            if tgt is not None:
                self.engine.write_mem(self.engine.xbox_ram_base + tgt, packed, mem)
            if mem: mem.close()
            e[4] = txt
            if eid in self.ui_row_widgets:
                self.ui_row_widgets[eid][5].config(bg="#A5D6A7")
                self.after(180, lambda: eid in self.ui_row_widgets and
                           self.ui_row_widgets[eid][5].config(bg="#FFFFFF"))

    def _commit_addr_change(self, eid, new_text):
        """Change the static address of a table entry."""
        entry = self._entry_by_id(eid)
        if entry is None: return
        old_off = entry[0]
        try:
            clean = new_text.strip().lower().replace("0x","").replace(" ","")
            if not clean: raise ValueError
            new_off = int(clean, 16)
            maxb = self.engine.xbox_ram_size_mb * 1024 * 1024
            if not (0 <= new_off < maxb): raise ValueError
            if new_off == old_off: return
            entry[0] = new_off
            entry[5] = False
            entry[6] = 0
            entry[7] = []
            entry[8] = new_off
            if eid in self.ui_row_widgets:
                for w in self.ui_row_widgets[eid]:
                    if isinstance(w, tk.Widget): w.destroy()
                del self.ui_row_widgets[eid]
            self._rebuild_table = True
            self.update_table_view()
        except:
            if eid in self.ui_row_widgets:
                ent = self.ui_row_widgets[eid][7]
                orig = getattr(ent, '_orig', f"0x{old_off:08X}")
                ent.delete(0, tk.END)
                ent.insert(0, orig)

    def _delete_entry(self, eid):
        """Remove an entry from the address table."""
        for i, e in enumerate(self.engine.address_table):
            if len(e) > 10 and e[10] == eid:
                del self.engine.address_table[i]
                break
        self._rebuild_table = True
        self.update_table_view()

    # ---- Multi-row selection ---------------------------------------------
    #
    # Row colours. The table is drawn from individual widgets rather than a
    # Treeview, so there is no built-in "selected" look - it is painted by
    # hand here. The Value entry is deliberately left alone: _commit_value
    # flashes it green and restores it to white, and tinting it too would mean
    # that flash restores the wrong colour on a selected row.
    ROW_BG        = "#151515"
    ROW_DESC_BG   = "#333333"
    SEL_BG        = "#0D3A5C"
    SEL_DESC_BG   = "#14507E"

    def _apply_row_highlight(self):
        """Repaint every visible row to match the current selection."""
        sel = self._selected_entry_ids
        for eid, widgets in list(self.ui_row_widgets.items()):
            try:
                chk, _, desc_ent, _, _, _, _, addr_ent = widgets
                on = eid in sel
                chk.config(bg=self.SEL_BG if on else self.ROW_BG)
                # A pointer row's address cell is readonly, and Tk draws a
                # readonly Entry with readonlybackground - setting bg on it
                # has no visible effect at all.
                if str(addr_ent.cget("state")) == "readonly":
                    addr_ent.config(
                        readonlybackground=self.SEL_BG if on else self.ROW_BG)
                else:
                    addr_ent.config(bg=self.SEL_BG if on else self.ROW_BG)
                desc_ent.config(
                    bg=self.SEL_DESC_BG if on else self.ROW_DESC_BG)
            except Exception:
                pass

    def _on_row_click(self, eid, event=None):
        """
        Update the selection for a click on a row.

        Plain click replaces the selection, Ctrl+click toggles a single row,
        Shift+click selects everything between the anchor and this row. The
        modifier bits come from event.state: 0x0001 is Shift, 0x0004 is
        Control on every platform Tk runs on.
        """
        state = getattr(event, "state", 0) if event is not None else 0
        try:
            ctrl = bool(state & 0x0004)
            shift = bool(state & 0x0001)
        except TypeError:
            ctrl = shift = False
        sel = self._selected_entry_ids

        if shift and self._sel_anchor in self._row_order and \
                eid in self._row_order:
            i = self._row_order.index(self._sel_anchor)
            j = self._row_order.index(eid)
            if i > j:
                i, j = j, i
            if not ctrl:
                sel.clear()
            sel.update(self._row_order[i:j + 1])
            # The anchor deliberately stays put, so dragging the shift-click
            # up and down re-picks the range instead of walking it along.
        elif ctrl:
            if eid in sel:
                sel.discard(eid)
            else:
                sel.add(eid)
            self._sel_anchor = eid
        else:
            sel.clear()
            sel.add(eid)
            self._sel_anchor = eid

        self._selected_entry_id = eid
        self._apply_row_highlight()
        return None

    def _on_row_right_click(self, eid, event, single_menu):
        """
        Post the row context menu, or the bulk menu when several are selected.

        Right-clicking a row that is not part of the current selection selects
        just that row first - the usual behaviour everywhere else, and it stops
        an action aimed at one row from silently hitting a selection made
        somewhere else in the table minutes ago.
        """
        if eid not in self._selected_entry_ids:
            self._on_row_click(eid)
        else:
            self._selected_entry_id = eid
        if len(self._selected_entry_ids) > 1:
            menu = self._build_multi_menu()
        else:
            menu = single_menu
        popup_menu(menu, event.x_root, event.y_root)
        return None

    def _selected_entries(self):
        """Selected entries, in on-screen order."""
        by_id = {e[10]: e for e in self.engine.address_table if len(e) > 10}
        out = [by_id[i] for i in self._row_order
               if i in self._selected_entry_ids and i in by_id]
        # Anything selected but not currently drawn (a collapsed group) still
        # counts - it is selected, the user just cannot see it.
        seen = {id(e) for e in out}
        out += [by_id[i] for i in self._selected_entry_ids
                if i in by_id and id(by_id[i]) not in seen]
        return out

    def _build_multi_menu(self):
        """Context menu for a multi-row selection."""
        n = len(self._selected_entry_ids)
        menu = tk.Menu(self, tearoff=0, bg="#424242", fg="#FFFFFF",
                       activebackground="#FF9800", activeforeground="#000000")
        menu.add_command(label=f"{n} entries selected", state="disabled")
        menu.add_separator()
        menu.add_command(label=f"Set value for all {n}…",
                         command=self._set_value_selected)
        menu.add_command(label=f"Freeze all {n}",
                         command=lambda: self._freeze_selected(True))
        menu.add_command(label=f"Unfreeze all {n}",
                         command=lambda: self._freeze_selected(False))
        menu.add_separator()
        move_menu = tk.Menu(menu, tearoff=0, bg="#424242", fg="#FFFFFF",
                            activebackground="#FF9800",
                            activeforeground="#000000")
        move_menu.add_command(label="None",
                              command=lambda: self._move_selected_to_group(""))
        if self.groups:
            move_menu.add_separator()
            for g in self.groups:
                move_menu.add_command(
                    label=g,
                    command=lambda gn=g: self._move_selected_to_group(gn))
        move_menu.add_separator()
        move_menu.add_command(label="New group…",
                              command=self._new_group_selected)
        menu.add_cascade(label=f"Move all {n} to group", menu=move_menu)
        menu.add_separator()
        menu.add_command(label=f"Remove all {n}  (Delete)",
                         command=self._delete_selected_entries)
        # Held on self: a Tk menu with no Python reference is garbage collected
        # right after posting and the menu vanishes mid-click.
        self._multi_menu = menu
        return menu

    def _delete_selected_entries(self, fallback_eid=None):
        """
        Remove every selected entry in one pass.

        Deleting one at a time through _delete_entry would rebuild the whole
        table once per row, which is slow and makes the list jump around while
        it works. Large deletions ask first, since there is no undo.
        """
        ids = set(self._selected_entry_ids)
        if not ids and fallback_eid is not None:
            ids = {fallback_eid}
        if not ids:
            return
        if len(ids) > 1 and not messagebox.askyesno(
                "Remove entries",
                f"Remove {len(ids)} entries from the address table?",
                parent=self):
            return
        self.engine.address_table[:] = [
            e for e in self.engine.address_table
            if not (len(e) > 10 and e[10] in ids)]
        self._selected_entry_ids.clear()
        self._selected_entry_id = None
        self._sel_anchor = None
        self._rebuild_table = True
        self.update_table_view()

    def _set_value_selected(self):
        """Write one value into every selected entry."""
        entries = self._selected_entries()
        if not entries:
            return
        txt = simpledialog.askstring(
            "Set value",
            f"New value for {len(entries)} selected "
            f"{'entry' if len(entries) == 1 else 'entries'}:",
            parent=self)
        if txt is None:
            return
        txt = txt.strip()
        # The rows may not share a type, so each one is packed against its own
        # type rather than packing once and reusing the bytes. A value that
        # does not fit a given row's type is skipped and reported at the end
        # instead of aborting the whole batch.
        failed = []
        try:
            mem = open(f"/proc/{self.engine.pid}/mem", "rb+") \
                  if self.engine.os_type == "Linux" else None
        except Exception:
            mem = None
        try:
            for e in entries:
                packed = self.engine.pack_freeze_data(txt, e[2])
                if not packed:
                    failed.append(e[1] or f"0x{e[0]:08X}")
                    continue
                tgt = self.engine.resolve_entry(e, mem)
                if tgt is None:
                    failed.append(e[1] or f"0x{e[0]:08X}")
                    continue
                self.engine.write_mem(self.engine.xbox_ram_base + tgt,
                                      packed, mem)
                e[4] = txt
                # A frozen row keeps writing e[4], so updating it above is what
                # makes the new value stick rather than being overwritten by
                # the freeze thread on its next pass.
        finally:
            if mem:
                mem.close()
        for e in entries:
            wid = self.ui_row_widgets.get(e[10])
            if wid:
                wid[5].config(bg="#A5D6A7")
        self.after(220, self._restore_value_backgrounds)
        if failed:
            shown = "\n".join(f"  • {d}" for d in failed[:12])
            if len(failed) > 12:
                shown += f"\n  … and {len(failed) - 12} more"
            messagebox.showwarning(
                "Set value",
                f"{len(failed)} of {len(entries)} entries could not be "
                f"written (bad value for their type, or unresolved "
                f"pointer):\n\n{shown}", parent=self)

    def _restore_value_backgrounds(self):
        for wid in list(self.ui_row_widgets.values()):
            try:
                wid[5].config(bg="#FFFFFF")
            except Exception:
                pass

    def _freeze_selected(self, on):
        """Turn freezing on or off for every selected entry."""
        for e in self._selected_entries():
            e[3] = bool(on)
            if on:
                # Freeze the value showing right now, matching what the
                # single-row checkbox does.
                wid = self.ui_row_widgets.get(e[10])
                if wid:
                    e[4] = wid[6].get().strip()
        self._rebuild_table = True
        self.update_table_view()

    def _move_selected_to_group(self, group):
        for e in self._selected_entries():
            while len(e) <= 9:
                e.append("")
            e[9] = group
        self._rebuild_table = True
        self.update_table_view()

    def _new_group_selected(self):
        name = simpledialog.askstring("New Group", "Group name:", parent=self)
        if name and name.strip():
            name = name.strip()
            if name not in self.groups:
                self.groups.append(name)
            self._move_selected_to_group(name)

    def _select_all_entries(self, event=None):
        """Ctrl+A selects every row - but not while typing in a field."""
        w = None
        try:
            w = self.focus_get()
        except Exception:
            pass
        if isinstance(w, (tk.Entry, tk.Text, ttk.Entry)):
            return None
        self._selected_entry_ids = {e[10] for e in self.engine.address_table
                                    if len(e) > 10}
        if self._row_order:
            self._sel_anchor = self._row_order[0]
        self._apply_row_highlight()
        return "break"

    def _guest_virtual_for(self, entry):
        """
        The GUEST VIRTUAL address an entry refers to, for watchpoints.

        gdb watches virtual addresses. Pointer entries already resolve in
        virtual space; plain entries hold a physical offset, so those go back
        through the page map in reverse.
        """
        try:
            steps = self.engine.resolve_chain_steps(entry, None)
        except Exception:
            steps = []
        if entry[5] and steps:
            last = steps[-1]
            if last.get('virtual') and last.get('addr') is not None:
                return last['addr']
            phys = last.get('phys')
        else:
            phys = entry[8]
        if phys is None:
            return None
        pm = self.engine.ensure_pagemap()
        return None if pm is None else pm.to_virt(phys)

    def _find_what_accesses(self, eid, kind="writes"):
        """Watch an address through xemu's gdbstub and log what touches it."""
        entry = next((e for e in self.engine.address_table
                      if len(e) > 10 and e[10] == eid), None)
        if entry is None:
            return
        va = self._guest_virtual_for(entry)
        if va is None:
            messagebox.showerror(
                "Find what accesses",
                "Could not work out a guest virtual address for this entry.\n"
                "The page map may be stale - reattach and try again.")
            return
        GdbWatchWindow(self, va, entry[1] or f"0x{va:08X}", kind=kind)

    def _clear_table_selection(self, event=None):
        """
        Drop the current row selection and any leftover text highlight.

        Two separate things look like "selected" here. One is the row Ctrl+C
        would copy. The other is text highlighted inside a Description or Value
        Entry, which Tk keeps drawn even after the widget loses focus - so
        clicking empty space left the highlight sitting there looking live.
        Clearing it means finding whichever Entry owns it, since selection is
        per-widget.
        """
        self._selected_entry_id = None
        self._selected_entry_ids.clear()
        self._sel_anchor = None
        self._apply_row_highlight()
        focused = None
        try:
            focused = self.focus_get()
        except Exception:
            pass

        def clear(w):
            if isinstance(w, (tk.Entry, ttk.Entry)):
                try:
                    if w.selection_present():
                        w.selection_clear()
                except Exception:
                    pass
            elif isinstance(w, tk.Text):
                try:
                    w.tag_remove("sel", "1.0", tk.END)
                except Exception:
                    pass
            for c in w.winfo_children():
                clear(c)
        clear(self.scrollable_inner)

        # Move focus off the field as well, so its caret stops blinking and any
        # pending edit is committed through the existing FocusOut handler.
        if isinstance(focused, (tk.Entry, tk.Text, ttk.Entry)):
            try:
                self.table_canvas.focus_set()
            except Exception:
                pass
        return None

    def _duplicate_entry(self, eid, select=True):
        """
        Copy an address-table entry, inserted directly below the original.

        Deep-copies the offsets list: a shallow copy would leave both entries
        sharing one list, so editing the chain on the copy would silently
        rewrite the original's too. The clone gets a fresh entry id (the key
        every other operation matches on) and a " (copy)" description.
        """
        for i, e in enumerate(self.engine.address_table):
            if len(e) > 10 and e[10] == eid:
                dup = list(e)
                dup[7] = list(e[7]) if isinstance(e[7], (list, tuple)) else []
                dup[1] = f"{e[1]} (copy)"
                dup[3] = False          # never inherit an active freeze
                dup[10] = self.engine._next_entry_id
                self.engine._next_entry_id += 1
                self.engine.address_table.insert(i + 1, dup)
                self._rebuild_table = True
                self.update_table_view()
                if select:
                    self._selected_entry_id = dup[10]
                return dup[10]
        return None

    def _copy_entry(self, eid=None):
        """Remember an entry for pasting, and put its details on the clipboard."""
        eid = eid if eid is not None else getattr(self, '_selected_entry_id', None)
        for e in self.engine.address_table:
            if len(e) > 10 and e[10] == eid:
                self._entry_clipboard = list(e)
                self._entry_clipboard[7] = list(e[7]) \
                    if isinstance(e[7], (list, tuple)) else []
                try:
                    if e[5]:
                        txt = (("V" if (len(e) > 11 and e[11]) else "P")
                               + f"->[0x{e[6]:08X}+"
                               + ",".join(f"{x:X}" for x in e[7]) + "]")
                    else:
                        txt = f"0x{e[8]:08X}"
                    self.clipboard_clear()
                    self.clipboard_append(f"{txt}  {e[1]}")
                except Exception:
                    pass
                return True
        return False

    def _paste_entry(self, event=None):
        """Paste the copied entry as a new row."""
        src = getattr(self, '_entry_clipboard', None)
        if not src:
            return
        dup = list(src)
        dup[7] = list(src[7]) if isinstance(src[7], (list, tuple)) else []
        dup[3] = False
        dup[10] = self.engine._next_entry_id
        self.engine._next_entry_id += 1
        self.engine.address_table.append(dup)
        self._rebuild_table = True
        self.update_table_view()

    def _on_table_copy(self, event=None):
        # Never steal Ctrl+C from a field the user is typing in.
        w = self.focus_get()
        if isinstance(w, (tk.Entry, tk.Text, ttk.Entry)):
            return None
        return "break" if self._copy_entry() else None

    def _on_table_paste(self, event=None):
        w = self.focus_get()
        if isinstance(w, (tk.Entry, tk.Text, ttk.Entry)):
            return None
        self._paste_entry()
        return "break"

    # ---- Group management -------------------------------------------------
    def _toggle_group(self, name):
        self.collapsed_groups[name] = not self.collapsed_groups.get(name, False)
        self._rebuild_table = True
        self.update_table_view()

    def _move_to_group(self, eid, group):
        e = self._entry_by_id(eid)
        if e is not None:
            while len(e) <= 9: e.append("")
            e[9] = group
            self._rebuild_table = True
            self.update_table_view()

    def _new_group(self, eid):
        name = simpledialog.askstring("New Group","Group name:", parent=self)
        if name and name.strip():
            name = name.strip()
            if name not in self.groups: self.groups.append(name)
            self._move_to_group(eid, name)

    def _rename_group(self, old):
        new = simpledialog.askstring("Rename Group", f"New name for '{old}':", parent=self)
        if new and new.strip() and new.strip() != old:
            new = new.strip()
            if new not in self.groups:
                idx = self.groups.index(old)
                self.groups[idx] = new
                for e in self.engine.address_table:
                    if e[9] == old: e[9] = new
                self._rebuild_table = True
                self.update_table_view()

    def _delete_group(self, name):
        for e in self.engine.address_table:
            if e[9] == name: e[9] = ""
        if name in self.groups: self.groups.remove(name)
        self._rebuild_table = True
        self.update_table_view()

    def _ungroup_all(self, name):
        for e in self.engine.address_table:
            if e[9] == name: e[9] = ""
        self._rebuild_table = True
        self.update_table_view()

    # ---- Pointer map save/load/compare ------------------------------------
    def _save_ptr_map(self):
        """
        Persist Snapshot A's pointer index to disk (.npz).

        Saving the index rather than the raw dump keeps the file to a few tens
        of MB instead of 64, and means you can close xemu, reboot the game and
        still run Stage 2 against the original snapshot.
        """
        if not getattr(self, 'ptr_map_a', None):
            messagebox.showinfo("Save Pointer Map",
                                "No active pointer index. Take Snapshot A first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".npz",
                                            filetypes=[("Pointer Index","*.npz")])
        if not path: return
        p = self.ptr_map_a
        np.savez_compressed(path, src=p.src, dst=p.dst,
                            meta=np.array([p.ram_size, p.xbe_base, p.xbe_size,
                                           self.ptr_target1], dtype=np.int64))
        messagebox.showinfo("Saved", f"Index saved ({len(p):,} pointers).")

    def _load_ptr_map(self):
        path = filedialog.askopenfilename(filetypes=[("Pointer Index","*.npz")])
        if not path: return
        try:
            z = np.load(path)
            p = PointerMap.__new__(PointerMap)
            p.src, p.dst = z['src'], z['dst']
            p._by_src = None
            p.ram_size, p.xbe_base, p.xbe_size, self.ptr_target1 = \
                (int(x) for x in z['meta'])
            self.ptr_map_a = p
            self.label_status.config(
                text=f"Loaded index: {len(p):,} pointers, "
                     f"target 0x{self.ptr_target1:08X}", fg="#4CAF50")
        except Exception as e:
            messagebox.showerror("Error", f"Could not load index:\n{e}")

    def _compare_maps(self):
        """
        Cross-boot scan: load two saved indexes and keep only the chains that
        resolve to the target in BOTH. This is the offline equivalent of the
        Snapshot A / Snapshot B workflow and the most reliable way to find a
        pointer that survives a console reset.
        """
        f1 = filedialog.askopenfilename(title="Index A",
                                        filetypes=[("Pointer Index","*.npz")])
        if not f1: return
        f2 = filedialog.askopenfilename(title="Index B",
                                        filetypes=[("Pointer Index","*.npz")])
        if not f2: return

        def load(path):
            z = np.load(path)
            p = PointerMap.__new__(PointerMap)
            p.src, p.dst, p._by_src = z['src'], z['dst'], None
            p.ram_size, p.xbe_base, p.xbe_size, tgt = (int(x) for x in z['meta'])
            return p, tgt

        try:
            pa, meta_t1 = load(f1)
            pb, meta_t2 = load(f2)
        except Exception as e:
            messagebox.showerror("Error", f"Could not load index:\n{e}")
            return
        if np.array_equal(pa.src, pb.src) and np.array_equal(pa.dst, pb.dst):
            messagebox.showerror(
                "Identical indexes",
                "These two files contain the same snapshot.\n\n"
                "Save Pointer Map writes whatever Snapshot A last built, so "
                "saving twice without re-running Snapshot A gives two copies "
                "of one dump. Take Snapshot A again after rebooting the game, "
                "then save the second file.")
            return
        # The stored target is whatever Snapshot A was given, so ask rather
        # than assume it matches the dump the user meant.
        t1 = self._ask_target("Index A target",
                              f"Address of the value in index A\n"
                              f"(stored: 0x{meta_t1:08X}):")
        if t1 is None: return
        t2 = self._ask_target("Index B target",
                              f"Address of the value in index B\n"
                              f"(stored: 0x{meta_t2:08X}):")
        if t2 is None: return
        max_off, depth = self._ptr_settings()
        tol = max(0, int(self.ptr_tolerance.get()))
        self.label_status.config(text="Comparing indexes...", fg="#FF9800")
        self.update_idletasks()

        def worker():
            try:
                kept = scan_chains_verified(pa, t1, pb, t2,
                                            max_offset=max_off,
                                            max_depth=depth, tolerance=tol,
                                            static_only=self.ptr_static_only.get())
                self.after(0, lambda: self._show_chains(
                    kept, f"Cross-boot verified chains ({len(kept)} found)"))
            except Exception as exc:
                self.after(0, lambda m=str(exc): messagebox.showerror("Error", m))
        threading.Thread(target=worker, daemon=True).start()

    def _apply_scan_region(self):
        """Push the selected scan region into the engine."""
        label = self.scan_region_var.get()
        entry = next((r for r in XBOX_SCAN_REGIONS if r[0] == label), None)
        if entry is None:
            return
        name, lo, hi, virtual = entry

        if lo == -1:                       # Custom range...
            txt = simpledialog.askstring(
                "Custom scan range",
                "Range as START-END in hex, e.g.\n\n"
                "  00500000-00700000     (physical)\n"
                "  V:00501AE0-006FFE7C   (virtual; prefix with V:)")
            if not txt:
                self.scan_region_var.set(self.engine.scan_region_name
                                         if self.engine.scan_pagemask is None
                                         else label)
                return
            txt = txt.strip()
            virtual = txt[:2].upper() == "V:"
            if virtual:
                txt = txt[2:]
            try:
                a, b = re.split(r'[-:\s]+', txt.strip(), maxsplit=1)
                lo = int(a.replace("0x", ""), 16)
                hi = int(b.replace("0x", ""), 16)
                if hi <= lo:
                    raise ValueError("end must be greater than start")
            except Exception as exc:
                messagebox.showerror("Bad range", f"Could not parse:\n{exc}")
                return
            name = f"{'V' if virtual else 'P'}:{lo:08X}-{hi:08X}"

        if not self.engine.set_scan_region(name, lo, hi, virtual):
            messagebox.showerror(
                "Region unavailable",
                "That region has no mapped pages.\n"
                "Virtual regions need the guest page tables, which are only\n"
                "readable once the game is running.")
            self.scan_region_var.set(XBOX_SCAN_REGIONS[0][0])
            self.engine.set_scan_region(XBOX_SCAN_REGIONS[0][0], None, None)
            self.label_scan_region.config(text="")
            return

        if self.engine.scan_pagemask is None:
            self.label_scan_region.config(text="whole RAM  (physical addresses)")
        else:
            mb = self.engine.scan_pagemask.sum() * 4096 / 1048576.0
            space = "virtual" if self.engine.scan_virtual else "physical"
            self.label_scan_region.config(
                text=f"{mb:.1f} MB  ({space} addresses)")
        try:
            self.results_tree.heading(
                "address", text=("Address (virtual)" if self.engine.scan_virtual
                                 else "Address"))
        except Exception:
            pass

    # ---- RAM dumping ------------------------------------------------------
    def dump_ram_to_file(self):
        """
        Write the emulated Xbox RAM to disk in one of three formats.

        Emulation is not paused while this runs, so the dump is a smear across
        a few hundred milliseconds rather than a true instant. That is fine for
        pointer work (chains are stable between frames) but do not trust it for
        catching a value mid-update.
        """
        path = filedialog.asksaveasfilename(
            defaultextension=".npz",
            filetypes=[("Analysis bundle (small)", "*.npz"),
                       ("Compressed raw dump", "*.xz"),
                       ("Raw dump", "*.bin")],
            title="Dump Xbox RAM")
        if not path:
            return

        tgt = None
        if path.lower().endswith(".npz"):
            s = simpledialog.askstring(
                "Target address (optional)",
                "Address of a value you care about, so the bundle can include\n"
                "the raw bytes around it. Leave blank to skip.")
            if s and s.strip():
                try:
                    clean = re.sub(r'[^0-9a-fA-F]', '', s.strip().lower())
                    tgt = int(clean[-8:], 16) if len(clean) > 8 else int(clean, 16)
                    if KSEG_BASE <= tgt:
                        tgt -= KSEG_BASE
                except Exception:
                    tgt = None

        self.label_status.config(text="Dumping RAM...", fg="#FF9800")
        self.update_idletasks()

        def worker():
            try:
                dump, maxb = self._dump_ram()
                if path.lower().endswith(".bin"):
                    with open(path, "wb") as f:
                        f.write(dump)
                    xemu_privs.reclaim(path)
                elif path.lower().endswith(".xz"):
                    import lzma
                    # preset 6 rather than 9: RAM dumps are mostly zero pages
                    # and incompressible texture data, so the extra levels cost
                    # minutes for a couple of percent.
                    with lzma.open(path, "wb", preset=6) as f:
                        f.write(dump)
                    xemu_privs.reclaim(path)
                else:
                    self._write_analysis_bundle(path, dump, maxb, tgt)
                size = os.path.getsize(path)
                self.after(0, lambda: self._dump_done(path, size))
            except Exception as exc:
                self.after(0, lambda m=str(exc):
                           messagebox.showerror("Error", m))
        threading.Thread(target=worker, daemon=True).start()

    def _write_analysis_bundle(self, path, dump, maxb, tgt):
        """
        A compact, self-describing subset of RAM for offline diagnosis.

        A full dump is 64-128 MB, which is unwieldy to move around. This keeps
        the parts that answer questions about pointer structure - the complete
        pointer index, where data actually lives, the XBE headers, and raw
        windows around the interesting addresses - and drops the bulk (texture
        and audio data), typically landing an order of magnitude smaller.
        """
        # The index MUST be built in virtual space, and the page tables must
        # travel with it. A physical-space index is unusable for pointer work
        # on this console, and without the tables it cannot be re-derived
        # offline: user space is 4KB-table mapped and those tables live at
        # scattered physical addresses well outside any raw window.
        pgm = XboxPageMap(dump)
        pgm = pgm if pgm.valid else None
        pm = PointerMap(dump, maxb, pagemap=pgm)
        arr = np.frombuffer(dump[:(maxb // 4) * 4], dtype='<u4')

        # Which 4 KB pages hold anything at all.
        pages = np.frombuffer(dump[:(maxb // 4096) * 4096],
                              dtype=np.uint8).reshape(-1, 4096)
        page_nonzero = pages.any(axis=1)

        # Every XBE header candidate, with what it claims about itself.
        xbe = []
        for off in range(0, min(maxb, 0x00800000), 0x1000):
            if dump[off:off + 4] == b'XBEH':
                # base is at +0x104, image size at +0x10C - +0x108 is
                # SizeOfHeaders and reading them as one '<II' grabs that instead
                b_ = struct.unpack_from('<I', dump, off + 0x104)[0]
                s_ = struct.unpack_from('<I', dump, off + 0x10C)[0]
                xbe.append((off, b_, s_))

        # Raw windows: around the target, and the head of each XBE candidate.
        slices, slice_meta = [], []

        def grab(start, length):
            start = max(0, min(start, maxb))
            end = min(maxb, start + length)
            if end > start:
                slice_meta.append((start, end - start))
                slices.append(np.frombuffer(dump[start:end], dtype=np.uint8))

        # Page directory plus every page table it references, so the exact
        # translation can be reconstructed from the bundle alone.
        grab(XboxPageMap.PD_PHYS, 0x1000)
        try:
            pdes = struct.unpack_from('<1024I', dump, XboxPageMap.PD_PHYS)
            seen_pt = set()
            for e in pdes:
                if (e & 1) and not (e & 0x80):
                    pt = e & 0xFFFFF000
                    if pt not in seen_pt and pt + 0x1000 <= maxb:
                        seen_pt.add(pt)
                        grab(pt, 0x1000)
        except Exception:
            pass

        if tgt is not None:
            grab(tgt - 0x10000, 0x20000)
        for off, _, _ in xbe[:4]:
            grab(off, 0x2000)
        grab(0, 0x100000)      # low 1 MB: kernel structures and early statics

        np.savez_compressed(
            path,
            ptr_src=pm.src, ptr_dst=pm.dst,
            page_nonzero=page_nonzero,
            xbe=np.array(xbe, dtype=np.int64).reshape(-1, 3),
            dword_hist=np.bincount(
                np.minimum(arr >> 20, 4095).astype(np.int64), minlength=4096),
            slice_meta=np.array(slice_meta, dtype=np.int64).reshape(-1, 2),
            slice_data=np.concatenate(slices) if slices
                       else np.zeros(0, dtype=np.uint8),
            target_virt=np.array(
                [-1 if (tgt is None or pgm is None or
                        pgm.to_virt(tgt) is None) else pgm.to_virt(tgt)],
                dtype=np.int64),
            index_is_virtual=np.array([1 if pgm is not None else 0],
                                      dtype=np.int64),
            meta=np.array([maxb, self.engine.xbox_ram_base or 0,
                           int(self.engine.pid or 0),
                           -1 if tgt is None else tgt,
                           int(time.time())], dtype=np.int64))

        # savez_compressed appends .npz when the path lacks that suffix, so
        # reclaim both candidate names rather than guessing which one landed.
        xemu_privs.reclaim(path if os.path.exists(path) else path + '.npz')

    def _dump_done(self, path, size):
        self.label_status.config(text=f"Attached! PID:{self.engine.pid}",
                                 fg="#4CAF50")
        messagebox.showinfo(
            "Dump complete",
            f"{os.path.basename(path)}\n{size / (1024*1024):.1f} MB written.")

    # ---- Manual pointer entry (Cheat Engine style) ------------------------
    def _edit_pointer_entry(self, entry):
        """Reopen a pointer row in the editor, located by identity."""
        for i, e in enumerate(self.engine.address_table):
            if e is entry:
                self.add_pointer_entry(edit_index=i)
                return

    def add_pointer_entry(self, edit_index=None):
        """
        Author a pointer chain by hand, like Cheat Engine's "Add Address
        Manually" with Pointer ticked.

        Offsets are listed bottom-up exactly as CE displays them: the last row
        is the base, the top row is the final offset applied to the value's
        address. The resolution preview updates as you type, so a wrong offset
        is visible immediately instead of after the entry is committed.
        """
        existing = None
        if edit_index is not None and 0 <= edit_index < len(self.engine.address_table):
            existing = self.engine.address_table[edit_index]

        win = tk.Toplevel(self)
        win.title("Edit pointer" if existing else "Add pointer")
        win.geometry("470x430")
        win.configure(bg="#212121")
        win.transient(self)

        tk.Label(win, text="Pointer chain", fg="#FF9800", bg="#212121",
                 font=("Helvetica", 11, "bold")).pack(pady=(12, 2))
        tk.Label(win, text="resolved as  [[base] + off] + off ...",
                 fg="#B0BEC5", bg="#212121",
                 font=("Helvetica", 8)).pack()

        # --- description + type ---
        top = tk.Frame(win, bg="#212121")
        top.pack(fill="x", padx=15, pady=(10, 4))
        tk.Label(top, text="Description:", fg="#E0E0E0", bg="#212121",
                 font=("Helvetica", 9)).grid(row=0, column=0, sticky="w")
        desc_var = tk.StringVar(value=existing[1] if existing else "Pointer")
        tk.Entry(top, textvariable=desc_var, width=28, bg="#424242",
                 fg="#FFFFFF", insertbackground="white", bd=0
                 ).grid(row=0, column=1, sticky="w", padx=6)
        tk.Label(top, text="Type:", fg="#E0E0E0", bg="#212121",
                 font=("Helvetica", 9)).grid(row=1, column=0, sticky="w", pady=4)
        type_var = tk.StringVar(
            value=existing[2] if existing else self.dropdown_type_var.get())
        ttk.Combobox(top, textvariable=type_var, state="readonly", width=14,
                     values=self.type_options).grid(row=1, column=1, sticky="w",
                                                    padx=6, pady=4)

        # Persisted on the entry (index 11). It used to be inferred from
        # "base >= 0x10000", which is true of every plausible base - so
        # unticking the box never survived a reopen.
        virt_var = tk.BooleanVar(
            value=(bool(existing[11]) if existing and len(existing) > 11
                   else True))
        tk.Checkbutton(win, text="Base is a virtual address (recommended)",
                       variable=virt_var, bg="#212121", fg="#4FC3F7",
                       selectcolor="#424242", activebackground="#212121",
                       activeforeground="#4FC3F7", font=("Helvetica", 8)
                       ).pack(anchor="w", padx=15)

        # --- offsets, bottom-up like CE ---
        off_frame = tk.LabelFrame(win, text=" Offsets (top = applied last) ",
                                  bg="#212121", fg="#FF9800", bd=1,
                                  font=("Helvetica", 8, "bold"))
        off_frame.pack(fill="both", expand=True, padx=15, pady=8)
        rows_holder = tk.Frame(off_frame, bg="#212121")
        rows_holder.pack(fill="both", expand=True, padx=8, pady=4)
        off_vars = []

        base_row = tk.Frame(win, bg="#212121")
        base_row.pack(fill="x", padx=15)
        tk.Label(base_row, text="Base address:  0x", fg="#E0E0E0", bg="#212121",
                 font=("Helvetica", 9, "bold")).pack(side="left")
        base_var = tk.StringVar(
            value=f"{existing[6]:08X}" if existing else "005FE4B0")
        tk.Entry(base_row, textvariable=base_var, width=12, bg="#424242",
                 fg="#00FF00", insertbackground="white", bd=0,
                 font=("Courier", 10, "bold")).pack(side="left", padx=4)

        preview = tk.Label(win, text="", fg="#B0BEC5", bg="#212121",
                           font=("Courier", 9), justify="left", anchor="w")
        preview.pack(fill="x", padx=15, pady=(8, 2))

        def parse_hex(txt, default=0):
            try:
                return int(re.sub(r'[^0-9a-fA-F]', '', str(txt).lower()) or "0", 16)
            except Exception:
                return default

        def current_chain():
            base = parse_hex(base_var.get())
            offs = [parse_hex(v.get()) for v in off_vars]
            return base, offs

        def refresh_preview(*_):
            base, offs = current_chain()
            if not offs:
                preview.config(text="Add at least one offset.", fg="#EF9A9A")
                return
            use_virt = virt_var.get() and self.engine.ensure_pagemap() is not None
            if virt_var.get() and not use_virt:
                preview.config(
                    text="Cannot read the guest page tables.\n"
                         "Is a game running? (untick the box to use physical\n"
                         "addresses instead)", fg="#EF9A9A")
                return
            steps = []
            cur = base
            ok = True
            for i, off in enumerate(offs):
                raw = (self.engine.read32_virt(cur) if use_virt
                       else self._read32_phys(cur))
                if raw is None:
                    steps.append(f"  [0x{cur:08X}] -> unreadable")
                    ok = False
                    break
                steps.append(f"  [0x{cur:08X}] = 0x{raw:08X}  + 0x{off:X}")
                cur = (raw + off) & 0xFFFFFFFF
            if ok:
                val = "?"
                addr = (self.engine.pagemap.to_phys(cur)
                        if use_virt and self.engine.pagemap else cur)
                if addr is not None:
                    try:
                        _, size = self.engine._get_type_params(
                            type_var.get(), "0")
                        raw = self.engine.read_mem(
                            self.engine.xbox_ram_base + addr, size)
                        val = self.engine.format_value(raw, type_var.get())
                    except Exception:
                        pass
                steps.append(f"  => 0x{cur:08X}   value: {val}")
            preview.config(text="\n".join(steps),
                           fg="#A5D6A7" if ok else "#EF9A9A")

        def rebuild_rows():
            for w in rows_holder.winfo_children():
                w.destroy()
            for i, var in enumerate(off_vars):
                r = tk.Frame(rows_holder, bg="#212121")
                r.pack(fill="x", pady=1)
                tk.Label(r, text=f"Offset {len(off_vars)-i}:  0x", fg="#E0E0E0",
                         bg="#212121", font=("Helvetica", 8)).pack(side="left")
                tk.Entry(r, textvariable=var, width=9, bg="#424242",
                         fg="#FFFFFF", insertbackground="white", bd=0,
                         font=("Courier", 9)).pack(side="left", padx=4)
                tk.Button(r, text="x", command=lambda k=i: remove_off(k),
                          bg="#B71C1C", fg="white", bd=0, padx=5,
                          font=("Helvetica", 7, "bold")).pack(side="left")
            refresh_preview()

        def add_off():
            v = tk.StringVar(value="0")
            v.trace_add("write", refresh_preview)
            off_vars.append(v)
            rebuild_rows()

        def remove_off(i):
            if 0 <= i < len(off_vars):
                off_vars.pop(i)
                rebuild_rows()

        for v in (existing[7] if existing and existing[7] else [0x88]):
            sv = tk.StringVar(value=f"{v:X}")
            sv.trace_add("write", refresh_preview)
            off_vars.append(sv)

        base_var.trace_add("write", refresh_preview)
        virt_var.trace_add("write", refresh_preview)
        type_var.trace_add("write", refresh_preview)

        tk.Button(off_frame, text="+ Add offset", command=add_off,
                  bg="#37474F", fg="white", bd=0, font=("Helvetica", 8),
                  padx=8).pack(pady=(0, 4))

        # --- commit ---
        def commit():
            base, offs = current_chain()
            if not offs:
                messagebox.showerror("Error", "A pointer needs at least one offset.")
                return
            use_virt = virt_var.get() and self.engine.ensure_pagemap() is not None
            resolved = (self.engine.resolve_pointer_chain_virt(base, offs)
                        if use_virt else
                        self.engine.resolve_pointer_chain(base, offs))
            entry = [resolved if resolved is not None else base,
                     desc_var.get() or "Pointer", type_var.get(),
                     existing[3] if existing else False,
                     existing[4] if existing else "0",
                     True, base, list(offs), base,
                     existing[9] if existing else "",
                     existing[10] if existing else self.engine._next_entry_id,
                     bool(virt_var.get())]
            if existing:
                self.engine.address_table[edit_index] = entry
            else:
                self.engine.address_table.append(entry)
                self.engine._next_entry_id += 1
            self._rebuild_table = True
            self.update_table_view()
            win.destroy()

        btns = tk.Frame(win, bg="#212121")
        btns.pack(fill="x", padx=15, pady=10)
        tk.Button(btns, text="OK", command=commit, bg="#4CAF50", fg="white",
                  font=("Helvetica", 9, "bold"), relief="flat", padx=18,
                  pady=4).pack(side="right")
        tk.Button(btns, text="Cancel", command=win.destroy, bg="#455A64",
                  fg="white", font=("Helvetica", 9, "bold"), relief="flat",
                  padx=12, pady=4).pack(side="left")

        rebuild_rows()

    def _read32_phys(self, off):
        """Read a dword at a physical offset, or None if out of range."""
        maxb = self.engine.xbox_ram_size_mb * 1024 * 1024
        if not (0 <= off < maxb - 3):
            return None
        try:
            raw = self.engine.read_mem(self.engine.xbox_ram_base + off, 4)
            return struct.unpack("<I", raw)[0] if len(raw) >= 4 else None
        except Exception:
            return None

    # ---- Guided pointer finder --------------------------------------------
    def pointer_wizard(self):
        """
        Step-by-step pointer finder that needs no knowledge of Xbox internals.

        Everything the manual flow makes the user understand is handled here:
        page tables are read automatically, the physical address from the viewer
        is translated to virtual silently, search depth and struct offset are
        escalated until something is found instead of being typed in, and each
        result is labelled by the XBE section its base lives in so "is this a
        good anchor?" is answerable without knowing what an XBE section is.
        """
        if not _HAVE_NUMPY:
            messagebox.showerror("Error", "The pointer finder requires numpy.")
            return

        win = tk.Toplevel(self)
        win.title("Find a Pointer - Guided")
        win.geometry("640x470")
        win.configure(bg="#212121")
        wiz = {'step': 1, 'addr1': None, 'addr2': None, 'chains': [],
               'map_a': None, 'sections': []}

        head = tk.Label(win, text="", fg="#FF9800", bg="#212121",
                        font=("Helvetica", 11, "bold"), anchor="w")
        head.pack(fill="x", padx=15, pady=(12, 4))
        body = tk.Label(win, text="", fg="#E0E0E0", bg="#212121",
                        font=("Helvetica", 9), justify="left", anchor="nw",
                        wraplength=600)
        body.pack(fill="x", padx=15)

        entry_row = tk.Frame(win, bg="#212121")
        entry_row.pack(fill="x", padx=15, pady=6)
        addr_lbl = tk.Label(entry_row, text="Address:", fg="#E0E0E0",
                            bg="#212121", font=("Helvetica", 9))
        addr_in = tk.Entry(entry_row, width=16, bg="#424242", fg="#FFFFFF",
                           insertbackground="white", bd=0,
                           font=("Courier", 10, "bold"))

        list_frame = tk.Frame(win, bg="#212121")
        results = tk.Listbox(list_frame, bg="#151515", fg="#00FF00",
                             font=("Courier", 9), activestyle="none")
        rsb = tk.Scrollbar(list_frame, command=results.yview, bg="#424242")
        results.config(yscrollcommand=rsb.set)

        code_box = tk.Text(win, height=4, bg="#151515", fg="#4FC3F7", bd=0,
                           font=("Courier", 10, "bold"))

        btn_row = tk.Frame(win, bg="#212121")
        btn_row.pack(side="bottom", fill="x", padx=15, pady=10)
        btn_next = tk.Button(btn_row, text="Next", bg="#4CAF50", fg="white",
                             font=("Helvetica", 9, "bold"), relief="flat",
                             padx=14, pady=4)
        btn_next.pack(side="right")
        tk.Button(btn_row, text="Close", command=win.destroy, bg="#455A64",
                  fg="white", font=("Helvetica", 9, "bold"), relief="flat",
                  padx=12, pady=4).pack(side="left")
        status = tk.Label(btn_row, text="", fg="#B0BEC5", bg="#212121",
                          font=("Helvetica", 8))
        status.pack(side="right", padx=10)

        def show_step():
            for w in (addr_lbl, addr_in):
                w.pack_forget()
            list_frame.pack_forget()
            code_box.pack_forget()
            if wiz['step'] == 1:
                head.config(text="Step 1 of 3  -  Where is your value?")
                body.config(text=(
                    "Find the value with a normal scan first, then type its "
                    "address here (or select a scan result before opening this "
                    "window).\n\n"
                    "Paste the address exactly as the scanner shows it. "
                    "Nothing else needs setting up."))
                addr_lbl.config(
                    text=("Address (virtual):"
                          if getattr(self.engine, 'scan_virtual', False)
                          else "Address:"))
                addr_lbl.pack(side="left")
                addr_in.pack(side="left", padx=6)
                addr_in.delete(0, tk.END)
                sel = self.listbox_results.curselection() \
                    if hasattr(self, 'listbox_results') else ()
                if sel and sel[0] < len(self.engine.scan_results):
                    addr_in.insert(0, "0x%08X" % self.engine.to_display_addr(
                        self.engine.scan_results[sel[0]]))
                btn_next.config(text="Next", state="normal")
            elif wiz['step'] == 2:
                head.config(text="Step 2 of 3  -  Make the value move")
                body.config(text=(
                    "Now make the game move the value somewhere else. The "
                    "quickest way is xemu's own save states:\n\n"
                    "   1. in xemu, load a save state (or save one and load "
                    "it back)\n"
                    "   2. re-find the value with a normal scan\n\n"
                    "Loading a state re-creates the game's objects, so the "
                    "address moves - no need to quit xemu or change level. "
                    "Restarting or changing level works too.\n\n"
                    "Type the new address below and press Search. This second "
                    "look is what separates a real pointer from coincidence."))
                addr_lbl.pack(side="left")
                addr_in.pack(side="left", padx=6)
                addr_in.delete(0, tk.END)
                btn_next.config(text="Search", state="normal")
            else:
                head.config(text="Step 3 of 3  -  Results")
                list_frame.pack(fill="both", expand=True, padx=15, pady=4)
                rsb.pack(side="right", fill="y")
                results.pack(side="left", fill="both", expand=True)
                code_box.pack(fill="x", padx=15, pady=(0, 4))
                btn_next.config(text="Add to Table", state="normal")

        def parse_addr():
            raw = addr_in.get().strip()
            if not raw:
                return None
            try:
                clean = re.sub(r'[^0-9a-fA-F]', '', raw.lower())
                return int(clean[-8:], 16) if len(clean) > 8 else int(clean, 16)
            except Exception:
                return None

        def to_virtual(pm, addr):
            """
            Normalise a user-entered address to virtual.

            Which space the number is in cannot be decided by inspection: most
            addresses are valid as BOTH a physical offset and a virtual address
            (0x00DD15C8 is both in a real dump), and translating an
            already-virtual address a second time yields a plausible, wrong
            answer. So use the scan region the user actually ran instead of
            guessing - if it was a [V] region, the scanner already showed them
            virtual addresses and no conversion is needed.
            """
            if pm is None:
                return addr
            if getattr(self.engine, 'scan_virtual', False):
                return addr                      # already virtual
            v = pm.to_virt(addr)
            return addr if v is None else v

        def do_step1():
            addr = parse_addr()
            if addr is None:
                messagebox.showerror("Error", "Enter the address of your value.")
                return
            status.config(text="reading page tables...")
            win.update_idletasks()

            def work():
                try:
                    dump, maxb = self._dump_ram()
                    pm = XboxPageMap(dump)
                    pm = pm if pm.valid else None
                    self.engine.pagemap = pm
                    xb, _ = detect_xbe_region(dump, maxb)
                    secs = parse_xbe_sections(dump, xb) if xb is not None else []
                    pmap = PointerMap(dump, maxb, pagemap=pm)
                    va = to_virtual(pm, addr)
                    self.after(0, lambda: after1(pm, secs, pmap, va))
                except Exception as exc:
                    self.after(0, lambda m=str(exc):
                               messagebox.showerror("Error", m))
            threading.Thread(target=work, daemon=True).start()

        def after1(pm, secs, pmap, va):
            status.config(text="")
            wiz.update(map_a=pmap, addr1=va, sections=secs)
            where = describe_address(va, secs, pm)
            if pm is None:
                messagebox.showwarning(
                    "Limited mode",
                    "Could not read the game's page tables - is the game "
                    "running?\\nThe search will still run but is less reliable.")
            if "XBE image" in where:
                if not messagebox.askyesno(
                        "Already permanent?",
                        f"That address is in {where}.\\n\\n"
                        "Addresses there are the same every boot, so you may "
                        "not need a pointer at all - you can use the address "
                        "directly.\\n\\nSearch for a pointer anyway?"):
                    win.destroy()
                    return
            wiz['step'] = 2
            show_step()
            body.config(text=body.cget("text") +
                        f"\\n\\nYour value is in: {where}")

        def do_step2():
            addr = parse_addr()
            if addr is None:
                messagebox.showerror("Error", "Enter the new address.")
                return
            btn_next.config(state="disabled")

            def work():
                try:
                    dump, maxb = self._dump_ram()
                    pmb = XboxPageMap(dump)
                    pmb = pmb if pmb.valid else None
                    pmap_b = PointerMap(dump, maxb, pagemap=pmb)
                    vb = to_virtual(pmb, addr)
                    # Escalate rather than making the user guess: widen the
                    # struct offset before the depth, since depth costs far more
                    # time and yields far more noise.
                    plan = [(1, 0x400), (2, 0x400), (2, 0x1000),
                            (3, 0x1000), (3, 0x4000), (4, 0x1000)]
                    found = []
                    for depth, moff in plan:
                        self.after(0, lambda d=depth, m=moff: status.config(
                            text=f"searching: {d} level(s), offsets to 0x{m:X}..."))
                        found = scan_chains_verified(
                            wiz['map_a'], wiz['addr1'], pmap_b, vb,
                            max_offset=moff, max_depth=depth)
                        if found:
                            break
                    self.after(0, lambda: after2(found, vb))
                except Exception as exc:
                    self.after(0, lambda m=str(exc):
                               (messagebox.showerror("Error", m),
                                btn_next.config(state="normal")))
            threading.Thread(target=work, daemon=True).start()

        def after2(found, vb):
            status.config(text="")
            btn_next.config(state="normal")
            if not found:
                messagebox.showinfo(
                    "Nothing found",
                    "No pointer survived the second check.\\n\\n"
                    "Most likely causes:\\n"
                    "  - the second address is not the same value\\n"
                    "  - the value is not reached through a pointer\\n"
                    "  - the game moved more than expected between looks\\n\\n"
                    "Try again and re-find the value carefully.")
                return
            # Shallow chains anchored in the XBE image first: those are both the
            # most likely to be real and the only ones a trainer code can use.
            secs = wiz['sections']

            def rank(c):
                base, offs = c
                inimg = any(lo <= base < hi for _, lo, hi, _, _ in secs)
                return (0 if inimg else 1, len(offs),
                        sum(abs(o) for o in offs))
            found.sort(key=rank)
            wiz.update(chains=found, addr2=vb, step=3)
            show_step()
            body.config(text=f"{len(found)} pointer(s) survived the second "
                             "check. The best candidates are listed first - "
                             "pick one to see its cheat code.")
            results.delete(0, tk.END)
            for base, offs in found[:300]:
                # "heap" was the catch-all for anything outside an XBE
                # section, which labelled kernel-window bases as heap and hid
                # the single most important fact about them.
                tag = next((nm for nm, lo, hi, _, _ in secs if lo <= base < hi),
                           None)
                pm = getattr(self.engine, 'pagemap_ptr', None) or \
                     getattr(self, '_ptr_map_a', None)
                if tag is None and pm is not None and getattr(pm, 'xbe_found',
                                                              False) \
                        and pm.xbe_base <= base < pm.xbe_base + pm.xbe_size:
                    # Inside the image, just not inside a NAMED section - still
                    # a fixed virtual address every boot, which "heap" denied.
                    tag = "XBE image, unnamed section - fixed every boot"
                if tag is None:
                    if 0x80000000 <= base < 0x88000000:
                        tag = "contiguous window - verify across a reboot"
                    elif 0xC0000000 <= base < 0xC0400000:
                        tag = "PAGE TABLES - not a usable base"
                    elif 0xD0000000 <= base < 0xD1000000:
                        tag = "KERNEL DATA - verify across a reboot"
                    elif base >= 0xF0000000:
                        tag = "hardware registers - not a usable base"
                    else:
                        tag = "heap"
                results.insert("end", f"[{base:08X}] " +
                               " ".join(f"+{o:X}" for o in offs) +
                               f"   ({tag}, {len(offs)} level"
                               f"{'s' if len(offs) > 1 else ''})")
            results.selection_set(0)
            show_code()

        def show_code(_evt=None):
            sel = results.curselection()
            if not sel:
                return
            base, offs = wiz['chains'][sel[0]]
            size = {1: 0, 2: 1, 4: 2}.get(
                getattr(self.engine, '_scan_item_size', 4), 2)
            code_box.config(state="normal")
            code_box.delete("1.0", tk.END)
            if len(offs) == 1 and base > 0x0FFFFFFF:
                # The virtual opcodes carry a 28-BIT address field. Masking a
                # 0x8xxxxxxx or 0xD0xxxxxx base to fit silently retargets the
                # code somewhere else entirely - 0xD006152C becomes 0x006152C.
                code_box.insert("end",
                                f"Base 0x{base:08X} does not fit the 28-bit "
                                f"address field of the\nvirtual code types, so "
                                f"no cheat code can express it.\n\n"
                                f"Use 'Add to Table' - the engine's own table "
                                f"resolves the full\n32-bit address.")
            elif len(offs) == 1:
                # Opcode 7, not A. Type A is a ONE-LINE 32-bit write: emitted as
                # 'A', the first line would overwrite the pointer itself with
                # the freeze value, and the second line would then be read as a
                # fresh code - a type 0 byte write into low physical memory.
                code_box.insert("end",
                                f"Trainer code (type 0x7, virtual pointer):\n"
                                f"  7{base:07X} vvvvvvvv\n"
                                f"  000{size}0000 {offs[0]:08X}\n"
                                f"(replace vvvvvvvv with the value to freeze)")
            elif base > 0x0FFFFFFF:
                code_box.insert("end",
                                f"Base 0x{base:08X} does not fit the 28-bit "
                                f"address field of the\nvirtual code types, so "
                                f"no cheat code can express it.\n\n"
                                f"Use 'Add to Table' instead.")
            elif len(offs) > 8:
                code_box.insert("end",
                                f"{len(offs)} levels - type 0x7 carries at most "
                                f"8 offsets.\nUse 'Add to Table' instead.")
            else:
                # Type 7 takes N offsets, not one: 00SS00NN then the offsets
                # two per line. Line count is 2 + ceil((N-1)/2), and getting it
                # wrong leaves a trailing line to be parsed as a fresh code.
                lines = [f"  7{base:07X} vvvvvvvv",
                         f"  00{size:02X}00{len(offs):02X} {offs[0]:08X}"]
                rest = list(offs[1:])
                if len(rest) % 2:
                    rest.append(0)
                for i in range(0, len(rest), 2):
                    lines.append(f"  {rest[i]:08X} {rest[i + 1]:08X}")
                code_box.insert("end",
                                f"Trainer code (type 0x7, {len(offs)} offsets):\n"
                                + "\n".join(lines)
                                + "\n(replace vvvvvvvv with the value to freeze)")
            code_box.config(state="disabled")

        results.bind("<<ListboxSelect>>", show_code)

        def add_selected():
            sel = results.curselection()
            if not sel:
                return
            base, offs = wiz['chains'][sel[0]]
            resolved = self.engine.resolve_pointer_chain_virt(base, offs)
            self.engine.address_table.append([
                resolved if resolved is not None else base,
                f"Ptr L{len(offs)} 0x{base:08X}",
                self.dropdown_type_var.get(), False, "0",
                True, base, list(offs), base, "", self.engine._next_entry_id])
            self.engine._next_entry_id += 1
            self._rebuild_table = True
            self.update_table_view()
            messagebox.showinfo("Added", "Pointer added to the address table.")

        def on_next():
            if wiz['step'] == 1:
                do_step1()
            elif wiz['step'] == 2:
                do_step2()
            else:
                add_selected()

        btn_next.config(command=on_next)
        show_step()

    # ---- Pointer finder ---------------------------------------------------
    def _ask_target(self, title, prompt):
        """Prompt for an address and normalize it to a RAM offset."""
        s = simpledialog.askstring(title, prompt)
        if not s:
            return None
        try:
            clean = re.sub(r'[^0-9a-fA-F]', '', s.strip().lower())
            val = int(clean[-8:], 16) if len(clean) > 8 else int(clean, 16)
        except Exception:
            messagebox.showerror("Error", "Invalid address")
            return None
        maxb = self.engine.xbox_ram_size_mb * 1024 * 1024
        if KSEG_BASE <= val < KSEG_BASE + maxb:
            val -= KSEG_BASE
        if not (0 <= val < maxb):
            messagebox.showerror("Error", f"Address is outside {maxb // (1024*1024)} MB of RAM")
            return None
        return val

    def _dump_ram(self):
        """Take a full snapshot of emulated Xbox RAM."""
        maxb = self.engine.xbox_ram_size_mb * 1024 * 1024
        mem = open(f"/proc/{self.engine.pid}/mem", "rb") \
              if self.engine.os_type == "Linux" else None
        try:
            return self.engine.read_mem(self.engine.xbox_ram_base, maxb, mem), maxb
        finally:
            if mem:
                mem.close()

    def _ptr_settings(self):
        """Read the scan tuning values out of the GUI."""
        try:
            max_off = int(str(self.ptr_max_offset.get()).strip().lower()
                          .replace("0x", ""), 16)
        except Exception:
            max_off = 0x1000
        return max(4, max_off), max(1, int(self.max_ptr_depth.get()))

    def pointer_stage1(self):
        """
        Snapshot A: dump RAM and build the reverse pointer index.

        This replaces the old Stage 1, which kept every dword below the RAM
        size as a "pointer node" (i.e. every small integer in the game) and
        then filtered on a 64 MB window that excluded nothing. Nothing usable
        ever survived to Stage 2.
        """
        if not _HAVE_NUMPY:
            messagebox.showerror("Error", "The pointer scanner requires numpy.")
            return
        tgt = self._ask_target("Snapshot A",
                               "Target address of the value (e.g. 0x01A2B3C4):")
        if tgt is None:
            return
        self.label_status.config(text="Building pointer index...", fg="#FF9800")
        self.update_idletasks()

        def scan_thread():
            try:
                dump, maxb = self._dump_ram()
                pm = XboxPageMap(dump)
                pm = pm if pm.valid else None
                self.engine.pagemap = pm
                pmap = PointerMap(dump, maxb, pagemap=pm)
                # The viewer reports physical offsets; the game's pointers hold
                # virtual addresses. Translate so both live in one space.
                tv = pm.to_virt(tgt) if pm else None
                self.ptr_map_a = pmap
                self.ptr_target1 = tv if tv is not None else tgt
                self.ptr_target1_phys = tgt
                self.after(0, lambda: self._stage1_done(pmap, tgt, tv))
            except Exception as exc:
                self.after(0, lambda m=str(exc): messagebox.showerror("Error", m))
        threading.Thread(target=scan_thread, daemon=True).start()

    def _stage1_done(self, pmap, tgt_phys, tgt_virt):
        self.label_status.config(text=f"Attached! PID:{self.engine.pid}", fg="#4CAF50")
        if pmap.virtual and tgt_virt is None:
            messagebox.showwarning(
                "Address not mapped",
                f"Physical 0x{tgt_phys:08X} has no virtual mapping in the page\n"
                "tables, so the game cannot be holding a pointer to it.\n"
                "Re-find the value and check the address.")
        space = (f"Virtual address space (page tables OK).\n"
                 f"Your 0x{tgt_phys:08X} is virtual 0x{tgt_virt:08X}.\n\n"
                 if pmap.virtual and tgt_virt is not None else
                 "WARNING: page tables not found; falling back to physical\n"
                 "offsets, which will not match the pointers a game stores.\n\n")
        messagebox.showinfo(
            "Snapshot A taken",
            space + f"Indexed {len(pmap):,} candidate pointers.\n\n"
            + (f"XBE image found at 0x{pmap.xbe_base:08X}, "
               f"size 0x{pmap.xbe_size:X}\n\n" if pmap.xbe_found else
               "XBE header NOT found - the static region is unknown, so leave\n"
               "'Only bases inside the XBE image' unchecked.\n\n") +
            "Now either:\n"
            "  - 'Scan Snapshot A' for chains from this dump alone, or\n"
            "  - restart the game / reload the level, re-find the value, then\n"
                "    run Stage 2 to verify chains against a second snapshot.")

    def multi_pointer_scan(self):
        """Search snapshot A for chains, without verification."""
        if not getattr(self, 'ptr_map_a', None):
            messagebox.showerror("Error", "Take Snapshot A first.")
            return
        max_off, depth = self._ptr_settings()
        self.label_status.config(text="Scanning pointer chains...", fg="#FF9800")
        self.update_idletasks()

        def scan_thread():
            try:
                chains = scan_chains(self.ptr_map_a, self.ptr_target1,
                                     max_offset=max_off, max_depth=depth,
                                     static_only=self.ptr_static_only.get())
                self.after(0, lambda: self._show_chains(
                    chains, "Pointer Chains (unverified - snapshot A only)"))
            except Exception as exc:
                self.after(0, lambda m=str(exc): messagebox.showerror("Error", m))
        threading.Thread(target=scan_thread, daemon=True).start()

    def pointer_stage2(self):
        """
        Snapshot B: re-resolve every candidate chain against a fresh dump.

        This is the step that makes the results trustworthy. A depth-3 scan on
        a single snapshot routinely yields thousands of coincidental chains;
        almost none of them survive a game restart.
        """
        if not getattr(self, 'ptr_map_a', None):
            messagebox.showerror("Error", "Take Snapshot A first.")
            return
        tgt2 = self._ask_target(
            "Snapshot B", "New address of the SAME value after restart/reload:")
        if tgt2 is None:
            return
        max_off, depth = self._ptr_settings()
        tol = max(0, int(self.ptr_tolerance.get()))
        self.label_status.config(text="Scanning and verifying...", fg="#FF9800")
        self.update_idletasks()

        def scan_thread():
            try:
                dump2, maxb = self._dump_ram()
                pmb = XboxPageMap(dump2)
                pmb = pmb if pmb.valid else None
                pmap_b = PointerMap(dump2, maxb, pagemap=pmb)
                t2 = tgt2                      # rebound: closure var is read-only
                if pmb is not None:
                    tv2 = pmb.to_virt(t2)
                    if tv2 is None:
                        raise RuntimeError(
                            f"Physical 0x{t2:08X} is not mapped in snapshot B")
                    t2 = tv2
                kept = scan_chains_verified(
                    self.ptr_map_a, self.ptr_target1, pmap_b, t2,
                    max_offset=max_off, max_depth=depth, tolerance=tol,
                    static_only=self.ptr_static_only.get())
                self.ptr_map_b = pmap_b
                self.after(0, lambda: self._show_chains(
                    kept, f"Verified pointer chains ({len(kept)} found)"))
            except Exception as exc:
                self.after(0, lambda m=str(exc): messagebox.showerror("Error", m))
        threading.Thread(target=scan_thread, daemon=True).start()

    def _show_chains(self, chains, title):
        """Result window: shows chains and can push one into the address table."""
        self.label_status.config(text=f"Attached! PID:{self.engine.pid}", fg="#4CAF50")
        if not chains:
            messagebox.showinfo("Done", "No pointer chains found.\n\n"
                                        "Try raising Max Struct Offset or Max Levels.")
            return
        # Shallower chains with smaller offsets are the ones worth trying first.
        chains = sorted(chains, key=lambda c: (len(c[1]), sum(abs(o) for o in c[1])))

        win = tk.Toplevel(self)
        win.title("Pointer Results")
        win.geometry("620x460")
        win.configure(bg="#212121")
        tk.Label(win, text=title, fg="#FF9800", bg="#212121",
                 font=("Helvetica", 10, "bold")).pack(pady=8)
        lb = tk.Listbox(lb_parent := tk.Frame(win, bg="#212121"),
                        bg="#151515", fg="#00FF00",
                        font=("Courier", 10, "bold"), selectmode="browse",
                        activestyle="none")
        lb_parent.pack(fill="both", expand=True, padx=15, pady=5)
        sb = tk.Scrollbar(lb_parent, command=lb.yview, bg="#424242")
        lb.config(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        lb.pack(side="left", fill="both", expand=True)

        shown = chains[:5000]
        for base, offs in shown:
            lb.insert("end", f"0x{base:08X} -> " +
                             " -> ".join(f"+0x{o:X}" for o in offs))
        if len(chains) > len(shown):
            tk.Label(win, text=f"(showing first {len(shown):,} of {len(chains):,})",
                     fg="#B0BEC5", bg="#212121", font=("Helvetica", 8)).pack()

        def add_selected():
            sel = lb.curselection()
            if not sel:
                return
            base, offs = shown[sel[0]]
            resolved = (self.engine.resolve_pointer_chain_virt(base, offs)
                        if self.engine.pagemap is not None else None)
            self.engine.address_table.append([
                resolved if resolved is not None else
                (self.engine.resolve_pointer_chain(base, offs) or base),
                f"Ptr L{len(offs)} 0x{base:08X}",
                self.dropdown_type_var.get(), False, "0",
                True, base, list(offs), base, "", self.engine._next_entry_id])
            self.engine._next_entry_id += 1
            self._rebuild_table = True
            self.update_table_view()

        bf = tk.Frame(win, bg="#212121")
        bf.pack(fill="x", padx=15, pady=8)
        tk.Button(bf, text="Add Selected to Table", command=add_selected,
                  font=("Helvetica", 9, "bold"), bg="#4CAF50", fg="white",
                  relief="flat", padx=10, pady=4).pack(side="left")
        tk.Button(bf, text="Close", command=win.destroy,
                  font=("Helvetica", 9, "bold"), bg="#455A64", fg="white",
                  relief="flat", padx=10, pady=4).pack(side="right")

    # ---- Memory viewer ----------------------------------------------------
    def open_debugger(self, address=None):
        """Alias - the window is the debugger now, the name predates it."""
        return self.open_disassembler(address)

    def open_code_patches(self):
        """Open the code patch window (writes go through the gdbstub)."""
        from .code_patch import open_code_patch_window
        return open_code_patch_window(self)

    def open_disassembler(self, address=None):
        """Open (or raise) the debugger / disassembly window."""
        w = getattr(self, 'disasm_win', None)
        if w is not None and w.winfo_exists():
            w.deiconify(); w.lift()
            if address:
                w.goto(address)
            return w
        self.disasm_win = DisassemblyWindow(self, self.engine, address)
        return self.disasm_win

    def open_mem_viewer(self, offset=0, virtual=False):
        """
        Open (or raise) the hex memory viewer at the given offset.

        With virtual=True the address is a GUEST VIRTUAL address and the tab's
        Virtual tickbox is switched on for you. Handing a virtual address to a
        tab in physical mode lands somewhere unrelated, so the flag has to
        travel with the address rather than being set by hand afterwards.

        The window is raised explicitly. It was only ever created here, never
        deiconified or lifted, so once it had been opened and then covered or
        minimised every later Browse added a tab to a window the user could
        not see - which looks exactly like the jump having done nothing.
        """
        if not hasattr(self, 'tabbed_viewer') or not self.tabbed_viewer or \
           not self.tabbed_viewer.win.winfo_exists():
            self.tabbed_viewer = TabbedMemoryViewer(self, self.engine)
        else:
            try:
                self.tabbed_viewer.win.deiconify()
                self.tabbed_viewer.win.lift()
                self.tabbed_viewer.win.focus_force()
            except Exception:
                pass
        return self.tabbed_viewer.add_tab_at(offset, virtual=virtual)

    def _on_sort_changed(self):
        self._rebuild_table = True
        self.update_table_view()

    def _on_hex_display_toggle(self):
        self._rebuild_table = True
        self.update_table_view()

