"""Main cheat manager window.

Extracted verbatim from xemu_cheats_trainer.py.
"""
from .prelude import *  # noqa: F401,F403
import os, sys, time, struct, platform, threading, re, json, configparser
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from .cheat_tree import SECTIONS, all_game_nodes, game_section, group_child, is_group, make_cheat, make_group, walk_cheats  # noqa: F401
from .codes import CheatEngine  # noqa: F401
from .config import Config
from . import cheatfiles  # noqa: F401
from .mem import XemuMemory  # noqa: F401
from .tree_ops import count_tree, enabled_cheats, group_paths, group_state, set_subtree_enabled, sort_key, sort_tree  # noqa: F401
from .ui_widgets import bind_wheel, bind_wheel_cycle, bind_wheel_number, install_clipboard_fix, popup_menu  # noqa: F401


class CheatManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Xemu Cheat Manager")
        self.geometry("800x500")
        self.configure(bg="#212121")
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TScrollbar", background="#424242", troughcolor="#212121",
                        arrowcolor="#FFFFFF", bordercolor="#212121")

        self.mem = XemuMemory()
        self.cheat_engine = CheatEngine(self.mem)

        self.games = []
        self.selected_game_idx = None
        self.active_game_idx = None   # which game is currently "activated"
        # Freeze loop tuning. 50 ms matches the old hardcoded Tk timer; values
        # down to 1 ms are usable because the loop is a thread, not an after().
        self.freeze_interval_ms = 50
        self._freeze_gen = 0
        self._freeze_thread = None
        self._freeze_last_ms = 0.0
        self._freeze_ticks = 0
        self._cheat_timers = {}   # block id -> after id
        # The freeze thread used to re-walk the cheat list on every pass. It
        # now reads a prebuilt list that the GUI swaps in on change; a tuple
        # assignment is atomic, so no lock is needed.
        self._active_blocks = ()
        self._autosave_id = None      # pending debounced write
        self._tree_items = {}         # treeview item id -> node
        self._tree_parent = {}        # treeview item id -> containing list

        # Load from INI, restore geometry
        saved_geom = Config.load(self.games)
        self.freeze_interval_ms = Config.load_freeze_ms()
        # [ASM] patches go through xemu's gdbstub so QEMU's JIT drops the
        # block it already translated; without that a code patch writes into
        # RAM and never executes.
        self.cheat_engine.gdb_enabled = Config.load_gdb_patching()
        n = self.cheat_engine.online_guard.load_whitelist(Config.base_dir())
        if n:
            print(f"[*] online whitelist: {n} permitted code(s)")
        self.games.sort(key=lambda g: g['name'].lower())
        # Cheats are NOT sorted on load any more. The stored order is the order
        # they were added in, and the sort control below reorders the view
        # without touching it, so switching back to "Order added" restores it.
        self._sort_mode = Config.load_sort_mode()
        if saved_geom:
            self.geometry(saved_geom)
        install_clipboard_fix(self)
        self._build_gui()
        self._check_connection()

    # ---------- GUI ----------
    def _build_gui(self):
        bottom = tk.Frame(self, bg="#212121")
        bottom.pack(side="bottom", fill="x", padx=5, pady=2)
        self.status_label = tk.Label(bottom, text="Detecting...",
                                     font=("Helvetica",10),
                                     fg="#B0BEC5", bg="#212121", anchor="w")
        self.status_label.pack(side="left", fill="x", expand=True)

        tk.Label(bottom, text="Freeze every", fg="#B0BEC5", bg="#212121",
                 font=("Helvetica",8)).pack(side="left", padx=(10,2))
        self.freeze_ms_var = tk.StringVar(value=str(self.freeze_interval_ms))
        ent = tk.Entry(bottom, textvariable=self.freeze_ms_var, width=5,
                       bg="#424242", fg="#FFFFFF", insertbackground="white",
                       bd=0, font=("Helvetica",8), justify="center")
        ent.pack(side="left")
        bind_wheel_number(ent, self.freeze_ms_var, 1, 5000, 1)
        tk.Label(bottom, text="ms", fg="#B0BEC5", bg="#212121",
                 font=("Helvetica",8)).pack(side="left", padx=(2,6))
        self.freeze_rate_label = tk.Label(bottom, text="", fg="#4CAF50",
                                          bg="#212121", font=("Helvetica",8))
        self.freeze_rate_label.pack(side="left")

        # [ASM] patches need the stub route or the JIT keeps running the block
        # it already translated. Exposed rather than hardcoded so a game that
        # dislikes having gdb attached can still be patched the raw way.
        self.gdb_patch_var = tk.BooleanVar(
            value=getattr(self.cheat_engine, 'gdb_enabled', True))

        def _apply_gdb_patch(*_):
            on = bool(self.gdb_patch_var.get())
            self.cheat_engine.gdb_enabled = on
            if not on:
                self.cheat_engine.gdb_close()

        self.gdb_patch_var.trace_add("write", _apply_gdb_patch)
        tk.Checkbutton(bottom, text="JIT-safe patches",
                       variable=self.gdb_patch_var, bg="#212121",
                       fg="#B0BEC5", selectcolor="#151515",
                       activebackground="#212121", activeforeground="#FFFFFF",
                       font=("Helvetica",8), bd=0, highlightthickness=0
                       ).pack(side="right", padx=(4,8))
        self.gdb_status_label = tk.Label(bottom, text="", fg="#FF9800",
                                         bg="#212121", font=("Helvetica",8))
        self.gdb_status_label.pack(side="right")

        def _apply_interval(*_):
            try:
                v = int(float(self.freeze_ms_var.get()))
            except Exception:
                return
            # 1 ms floor: below that the thread spends all its time in
            # syscalls and the writes stop keeping up anyway.
            self.freeze_interval_ms = max(1, min(v, 5000))
        self.freeze_ms_var.trace_add("write", _apply_interval)

        def _tick_rate():
            n = self._freeze_ticks
            prev = getattr(self, "_freeze_prev_ticks", 0)
            self._freeze_prev_ticks = n
            hz = n - prev
            if self._freeze_thread is not None and self._freeze_thread.is_alive():
                self.freeze_rate_label.config(
                    text=f"{hz}/s  ({self._freeze_last_ms:.2f} ms/pass)")
            else:
                self.freeze_rate_label.config(text="")
            self.after(1000, _tick_rate)
        self.after(1000, _tick_rate)

        paned = tk.PanedWindow(self, orient=tk.HORIZONTAL, bg="#212121", sashrelief=tk.RAISED)
        paned.pack(fill="both", expand=True, padx=10, pady=10)

        # ---- left frame: game list ----
        left_frame = tk.Frame(paned, bg="#212121", width=250)
        paned.add(left_frame, stretch="never")

        tk.Label(left_frame, text="Games", font=("Helvetica",11,"bold"),
                 fg="#FF9800", bg="#212121").pack(pady=(5,2))

        # exportselection=False is load-bearing. By default a Listbox owns the
        # X PRIMARY selection, and it DROPS its own highlight the moment
        # another widget claims PRIMARY - such as the Entry inside a
        # simpledialog. That fired <<ListboxSelect>> with an empty selection,
        # which set selected_game_idx to None and blanked the cheat pane. It
        # looked like Rename ate the list; really the dialog stole the
        # selection out from under it.
        search_f = tk.Frame(left_frame, bg="#212121")
        search_f.pack(fill="x", padx=5, pady=(0, 2))
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(search_f, textvariable=self.search_var,
                                     bg="#424242", fg="#FFFFFF",
                                     insertbackground="white", bd=0,
                                     font=("Helvetica", 9))
        self.search_entry.pack(side="left", fill="x", expand=True)
        tk.Button(search_f, text="\u2715", command=self._clear_search,
                  font=("Helvetica", 8, "bold"), bg="#616161", fg="white",
                  relief="flat", padx=4).pack(side="left", padx=(3, 0))
        self.search_count = tk.Label(left_frame, text="", fg="#78909C",
                                     bg="#212121", font=("Helvetica", 8))
        self.search_count.pack(anchor="e", padx=6)
        self.search_var.trace_add("write", self._on_search_change)
        # Enter jumps straight to the first match, so a search can be driven
        # entirely from the keyboard.
        self.search_entry.bind("<Return>", lambda e: self._select_first_match())
        self.search_entry.bind("<Escape>", lambda e: self._clear_search())
        self.search_entry.bind("<Down>",
                               lambda e: (self.game_listbox.focus_set(),
                                          self._select_first_match()))

        self.game_listbox = tk.Listbox(left_frame, bg="#151515", fg="#FFFFFF",
                                       font=("Helvetica",10),
                                       exportselection=False,
                                       selectbackground="#333333")
        self.game_listbox.pack(fill="both", expand=True, padx=5, pady=5)
        self.game_listbox.bind("<<ListboxSelect>>", self._on_game_select)
        self.game_listbox.bind("<Double-Button-1>", self._on_game_double_click)

        btn_frame = tk.Frame(left_frame, bg="#212121")
        btn_frame.pack(fill="x", padx=5, pady=5)
        tk.Button(btn_frame, text="Add Game", command=self._add_game,
                  font=("Helvetica",9,"bold"), bg="#4CAF50", fg="white", relief="flat").pack(side="left", padx=2)
        tk.Button(btn_frame, text="Remove", command=self._remove_game,
                  font=("Helvetica",9,"bold"), bg="#f44336", fg="white", relief="flat").pack(side="left", padx=2)

        # ---- right frame: cheat tree ----
        right_frame = tk.Frame(paned, bg="#212121")
        paned.add(right_frame, stretch="always")

        self.section_heading = tk.Label(right_frame, text="Cheats",
                                        font=("Helvetica", 11, "bold"),
                                        fg="#FF9800", bg="#212121")
        self.section_heading.pack(pady=(5, 2))

        # Author and description get their own panels here rather than trailing
        # off the end of the row label, where a long name pushed them out of
        # sight and a description had nowhere to go at all.
        meta_frame = tk.Frame(right_frame, bg="#212121")
        meta_frame.pack(fill="x", padx=5, pady=(0,4))
        meta_frame.grid_columnconfigure(1, weight=1)

        # Game ID sits above Author. It belongs to the selected game, not to
        # the selected cheat, so it is filled in by _display_cheats and is NOT
        # cleared by _clear_meta_boxes when the cheat selection changes.
        #
        # An Entry rather than a Label: read-only still allows select-and-copy,
        # which is the whole point of showing an id. state="readonly" blocks
        # typing, so it cannot drift from the value the files are keyed on.
        tk.Label(meta_frame, text="Game ID:", fg="#FF9800", bg="#212121",
                 font=("Helvetica",9,"bold"), anchor="w").grid(
                     row=0, column=0, sticky="w", padx=(2,6))
        self.gameid_var = tk.StringVar(value="\u2014")
        self.gameid_box = tk.Entry(meta_frame, textvariable=self.gameid_var,
                                   state="readonly", readonlybackground="#1A1A1A",
                                   fg="#E0E0E0", bg="#1A1A1A",
                                   font=("Consolas",9), bd=1, relief="flat",
                                   highlightthickness=0,
                                   disabledforeground="#616161")
        self.gameid_box.grid(row=0, column=1, sticky="ew", pady=1, ipady=2)

        tk.Label(meta_frame, text="Author:", fg="#FF9800", bg="#212121",
                 font=("Helvetica",9,"bold"), anchor="w").grid(
                     row=1, column=0, sticky="w", padx=(2,6))
        self.author_box = tk.Label(meta_frame, text="", fg="#E0E0E0",
                                   bg="#1A1A1A", font=("Helvetica",9),
                                   anchor="w", bd=1, relief="flat",
                                   padx=6, pady=3)
        self.author_box.grid(row=1, column=1, sticky="ew", pady=1)

        tk.Label(meta_frame, text="Description:", fg="#FF9800", bg="#212121",
                 font=("Helvetica",9,"bold"), anchor="nw").grid(
                     row=2, column=0, sticky="nw", padx=(2,6), pady=(3,0))
        self.desc_box = tk.Message(meta_frame, text="", fg="#E0E0E0",
                                   bg="#1A1A1A", font=("Helvetica",9),
                                   anchor="w", justify="left", bd=1,
                                   relief="flat", padx=6, pady=3)
        self.desc_box.grid(row=2, column=1, sticky="ew", pady=1)
        # A Message wraps to a fixed pixel width, so it has to be retold the
        # width whenever the pane is resized or long text spills sideways.
        self.desc_box.bind(
            "<Configure>",
            lambda e: e.widget.configure(width=max(120, e.width - 12)))
        self._clear_meta_boxes()      # start on the placeholder, not blank

        # ---- Cheats / Patches tabs ----
        # A Notebook used purely as a tab strip: both pages are empty and the
        # one Treeview below shows whichever section is selected. Two real pages
        # would mean two Treeviews and two copies of every binding, menu and
        # editor in this class - the tree does not care which list it is showing,
        # so there is no reason to have two of it.
        self.section_var = tk.StringVar(value="cheats")
        self.section_tabs = ttk.Notebook(right_frame, height=1)
        self._section_pages = {}
        for key, label in (("cheats", "  Cheats  "), ("patches", "  Patches  ")):
            page = ttk.Frame(self.section_tabs, height=1)
            self.section_tabs.add(page, text=label)
            self._section_pages[key] = page
        self.section_tabs.pack(fill="x", padx=5, pady=(2, 0))
        self.section_tabs.bind("<<NotebookTabChanged>>", self._on_section_change)

        container = ttk.Frame(right_frame)
        container.pack(fill="both", expand=True, padx=5, pady=5)

        # A Treeview instead of a frame full of Checkbuttons. The old pane
        # destroyed and rebuilt one Frame + Checkbutton + 2 Buttons per cheat
        # every time a game was selected, which is four widgets per cheat and
        # visibly slow past a few hundred. The tree reuses its rows, and it is
        # what makes nesting possible at all.
        style = ttk.Style()
        style.configure("Cheats.Treeview", background="#151515",
                        fieldbackground="#151515", foreground="#E0E0E0",
                        rowheight=22, borderwidth=0)
        style.map("Cheats.Treeview",
                  background=[("selected", "#37474F")],
                  foreground=[("selected", "#FFFFFF")])
        style.layout("Cheats.Treeview", [('Cheats.Treeview.treearea',
                                          {'sticky': 'nswe'})])

        self.cheat_tree = ttk.Treeview(container, style="Cheats.Treeview",
                                       show="tree", selectmode="extended")
        self.cheat_scrollbar = ttk.Scrollbar(container, orient="vertical",
                                             command=self.cheat_tree.yview)
        self.cheat_tree.configure(yscrollcommand=self.cheat_scrollbar.set)
        self.cheat_tree.pack(side="left", fill="both", expand=True)
        self.cheat_scrollbar.pack(side="right", fill="y")

        # Width of the checkbox glyph plus its trailing space, in pixels, so
        # the clickable zone matches what is drawn rather than a guessed 20px.
        try:
            import tkinter.font as tkfont
            f = tkfont.nametofont(
                ttk.Style().lookup("Cheats.Treeview", "font") or "TkDefaultFont")
            self._glyph_w = max(14, f.measure("\u2611 "))
        except Exception:
            self._glyph_w = 18

        self.cheat_tree.tag_configure("group", foreground="#FFB74D")
        self.cheat_tree.tag_configure("cheat", foreground="#E0E0E0")
        self.cheat_tree.tag_configure("on", foreground="#A5D6A7")

        self.cheat_tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.cheat_tree.bind("<Button-1>", self._on_tree_click)
        self.cheat_tree.bind("<Double-Button-1>", self._on_tree_double_click)
        self.cheat_tree.bind("<space>", self._on_tree_space)
        self.cheat_tree.bind("<Return>", self._on_tree_space)
        self.cheat_tree.bind("<Delete>", lambda e: self._delete_selected())
        self.cheat_tree.bind("<Button-3>", self._on_tree_menu)
        self.cheat_tree.bind("<<TreeviewOpen>>", self._on_tree_open_close)
        self.cheat_tree.bind("<<TreeviewClose>>", self._on_tree_open_close)
        self.cheat_tree.bind("<Control-c>", lambda e: self._copy_selected())
        self.cheat_tree.bind("<Control-C>", lambda e: self._copy_selected())
        self.cheat_tree.bind("<Control-v>", self._paste_code)
        self.cheat_tree.bind("<Control-V>", self._paste_code)
        # Also on the window, so the hotkeys work without first clicking into
        # the tree. install_clipboard_fix() owns Ctrl+C/V inside Entry and Text
        # widgets and breaks out of them, so typing in a dialog is unaffected.
        self.bind("<Control-c>", self._copy_if_tree_focused)
        self.bind("<Control-v>", self._paste_if_tree_focused)
        # On X11 the wheel arrives as Button-4/5, which ttk.Treeview does not
        # handle - so the wheel only worked over the scrollbar. Bind both.
        bind_wheel(self.cheat_tree,
                   lambda d: self.cheat_tree.yview_scroll(d * 3, "units"))
        # Drag to reparent, PJ64 style.
        self.cheat_tree.bind("<ButtonPress-1>", self._on_drag_start, add="+")
        self.cheat_tree.bind("<B1-Motion>", self._on_drag_motion)
        self.cheat_tree.bind("<ButtonRelease-1>", self._on_drag_drop)
        self._drag = None

        ctrl_frame = tk.Frame(right_frame, bg="#212121")
        ctrl_frame.pack(fill="x", padx=5, pady=5)
        # Gridded in rows of six rather than packed left-to-right: eleven
        # buttons on one line ran past the edge of the pane and the last of
        # them were unreachable at the default window size.
        buttons = (
                ("Add Cheat",  self._add_cheat,      "#8BC34A", "black"),
                ("Add Group",  self._add_group,      "#FFB300", "black"),
                ("Edit",       self._edit_selected,  "#2196F3", "white"),
                ("Copy",       self._copy_selected,  "#5C6BC0", "white"),
                ("Paste",      self._paste_code,     "#26A69A", "black"),
                ("Delete",     self._delete_selected,"#f44336", "white"),
                ("Reload File",self._reload_cheats,  "#00897B", "white"),
                ("Group\u2026",   self._move_to_group_dialog, "#7E57C2", "white"),
                ("Ungroup",    self._move_selected_to_root, "#8D6E63", "white"),
                ("Enable All", self._enable_all,     "#FF9800", "black"),
                ("Disable All",self._disable_all,    "#607D8B", "white"))
        per_row = 6
        for i, (text, cmd, bg, fg) in enumerate(buttons):
            tk.Button(ctrl_frame, text=text, command=cmd,
                      font=("Helvetica",9,"bold"), bg=bg, fg=fg,
                      relief="flat").grid(row=i // per_row, column=i % per_row,
                                          sticky="ew", padx=2, pady=2)
        for c in range(per_row):
            ctrl_frame.grid_columnconfigure(c, weight=1, uniform="cheatbtns")

        sort_f = tk.Frame(ctrl_frame, bg="#212121")
        sort_f.grid(row=(len(buttons) - 1) // per_row, column=per_row,
                    sticky="e", padx=4)
        tk.Label(sort_f, text="Sort:", fg="#B0BEC5", bg="#212121",
                 font=("Helvetica",8)).pack(side="left")
        self.sort_var = tk.StringVar(value=self._sort_mode)
        sort_menu = tk.OptionMenu(sort_f, self.sort_var,
                                  "Order added", "Alphabetical",
                                  command=lambda *_: self._on_sort_change())
        sort_menu.config(font=("Helvetica",8), bg="#424242", fg="#E0E0E0",
                         highlightthickness=0, bd=0, activebackground="#616161")
        sort_menu.pack(side="left", padx=2)   # inside sort_f, which is gridded
        bind_wheel_cycle(sort_menu, ["Order added", "Alphabetical"],
                         self.sort_var.get,
                         lambda v: (self.sort_var.set(v), self._on_sort_change()))

        self._refresh_game_list()

    def _on_sort_change(self):
        self._sort_mode = self.sort_var.get()
        self._display_cheats(self.selected_game_idx)
        self._save_autosave()

    def _ordered(self, nodes):
        """View order. Returns a COPY when sorting, so the list itself keeps
        its insertion order and "Order added" stays recoverable."""
        if self._sort_mode == "Alphabetical":
            return sorted(nodes, key=sort_key)
        return list(nodes)

    def _refresh_game_list(self):
        """
        Repopulate the game list, honouring the search box.

        With a filter in play the listbox no longer lines up with self.games,
        so _row_to_game holds the mapping. Everything that reads
        curselection() goes through it - taking a listbox row as an index into
        self.games is exactly the bug that used to show one game's cheats while
        another was highlighted.
        """
        keep = self.selected_game_idx
        keep_game = self.games[keep] if keep is not None and \
            keep < len(self.games) else None

        self.game_listbox.delete(0, tk.END)
        self.games.sort(key=lambda g: g['name'].lower())
        needle = (self.search_var.get() if hasattr(self, 'search_var')
                  else "").strip().lower()
        self._row_to_game = []
        for i, game in enumerate(self.games):
            if needle and needle not in game['name'].lower():
                continue
            # An asterisk marks the game whose cheats are actually live, so it
            # stays identifiable while you scroll or search elsewhere.
            prefix = "* " if game.get('active') else "   "
            self.game_listbox.insert(tk.END, prefix + game['name'])
            self._row_to_game.append(i)

        self.active_game_idx = next(
            (i for i, g in enumerate(self.games) if g.get('active')), None)
        if keep_game is not None:
            try:
                self.selected_game_idx = self.games.index(keep_game)
            except ValueError:
                self.selected_game_idx = None
            row = self._game_to_row(self.selected_game_idx)
            if row is not None:
                self.game_listbox.selection_clear(0, tk.END)
                self.game_listbox.selection_set(row)
                self.game_listbox.see(row)
        self._refresh_game_list_visuals()

    def _game_to_row(self, gidx):
        if gidx is None:
            return None
        try:
            return self._row_to_game.index(gidx)
        except (ValueError, AttributeError):
            return None

    def _row_to_game_index(self, row):
        try:
            return self._row_to_game[row]
        except (IndexError, AttributeError):
            return None

    def _on_search_change(self, *_):
        self._refresh_game_list()
        self.search_count.config(
            text=f"{len(self._row_to_game)}/{len(self.games)}")

    def _select_first_match(self):
        if not getattr(self, '_row_to_game', []):
            return "break"
        self.game_listbox.selection_clear(0, tk.END)
        self.game_listbox.selection_set(0)
        self.game_listbox.see(0)
        self._on_game_select(None)
        return "break"

    def _clear_search(self):
        self.search_var.set("")
        self.game_listbox.focus_set()

    def _refresh_game_list_visuals(self):
        """Update colours/markers to show which game is active."""
        for row, gidx in enumerate(getattr(self, '_row_to_game', [])):
            if self.games[gidx].get('active', False):
                self.game_listbox.itemconfig(row, bg="#1B5E20", fg="#A5D6A7")
            else:
                self.game_listbox.itemconfig(row, bg="#151515", fg="#FFFFFF")

    def _on_game_select(self, event):
        sel = self.game_listbox.curselection()
        if not sel:
            # An empty selection means focus moved elsewhere, not that the user
            # deselected the game. Keep showing what they were looking at.
            return
        idx = self._row_to_game_index(sel[0])
        if idx is None:
            return
        self.selected_game_idx = idx
        self._display_cheats(idx)

    def _activate_game(self, idx):
        """Set game at idx as active and start its enabled cheats."""
        if idx < 0 or idx >= len(self.games):
            return
        game = self.games[idx]
        # A journal from a different title cannot be restored into this one.
        if self.active_game_idx not in (None, idx):
            self.cheat_engine.clear_asm_journal()
        game['active'] = True
        self.active_game_idx = idx
        self._rebuild_active_blocks()
        self._ensure_freeze_thread()
        self._save_autosave()

    def _deactivate_game(self, idx):
        """Deactivate game at idx and stop all its cheat timers."""
        if idx < 0 or idx >= len(self.games):
            return
        game = self.games[idx]
        game['active'] = False
        for blk in all_game_nodes(game):
            self._stop_cheat_timer(blk)
        if self.active_game_idx == idx:
            self.active_game_idx = None
        self._rebuild_active_blocks()
        self._save_autosave()

    # ---- Freeze loop ------------------------------------------------------
    #
    # A single background thread applies every enabled cheat, instead of one
    # Tk `after` timer per cheat. Tk timers cannot be driven at 1 ms - the
    # event loop coalesces them and the GUI starves - and the old loop also
    # reopened /proc/<pid>/mem on every tick, which dominates the cost at high
    # rates. One thread with one persistent handle removes both limits.

    def _freeze_worker(self, gen):
        mem_file = None
        pid_open = None
        try:
            while gen == self._freeze_gen:
                interval = max(0.0005, self.freeze_interval_ms / 1000.0)
                # Prebuilt by the GUI on every change. The old loop rebuilt a
                # filtered list from the cheat list on every single pass, which
                # at 1 ms means a full walk a thousand times a second for a
                # result that only changes when a checkbox does.
                blocks = self._active_blocks
                if not blocks:
                    time.sleep(0.05)
                    continue
                try:
                    if self.mem.os_type == 'Linux' and self.mem.pid:
                        if mem_file is None or pid_open != self.mem.pid:
                            if mem_file:
                                mem_file.close()
                            mem_file = open(f"/proc/{self.mem.pid}/mem",
                                            "rb+", buffering=0)
                            pid_open = self.mem.pid
                    t0 = time.perf_counter()
                    execute = self.cheat_engine.execute_block
                    for blk in blocks:
                        execute(blk, mem_file)
                    self._freeze_last_ms = (time.perf_counter() - t0) * 1000.0
                    self._freeze_ticks += 1
                except Exception:
                    # A dead handle (game closed, PID changed) must not kill
                    # the loop - drop it and let the next pass reopen.
                    if mem_file:
                        try: mem_file.close()
                        except Exception: pass
                    mem_file = None
                    pid_open = None
                    time.sleep(0.05)
                    continue
                time.sleep(interval)
        finally:
            if mem_file:
                try: mem_file.close()
                except Exception: pass

    def _ensure_freeze_thread(self):
        """Start the freeze thread if it is not already running."""
        if getattr(self, '_freeze_thread', None) is not None and \
                self._freeze_thread.is_alive():
            return
        self._freeze_gen = getattr(self, '_freeze_gen', 0) + 1
        gen = self._freeze_gen
        self._freeze_thread = threading.Thread(
            target=self._freeze_worker, args=(gen,), daemon=True)
        self._freeze_thread.start()

    def _start_cheat_timer(self, blk):
        """Kept for compatibility - the worker picks up enabled blocks itself."""
        self._ensure_freeze_thread()

    def _stop_cheat_timer(self, blk):
        """Cancel any legacy Tk timer left on a block."""
        tid = blk.pop('_timer_id', None)
        if tid is not None:
            try: self.after_cancel(tid)
            except Exception: pass

    def _on_game_double_click(self, event):
        """Double‑click a game to toggle its active state."""
        sel = self.game_listbox.curselection()
        if not sel:
            return
        idx = self._row_to_game_index(sel[0])
        if idx is None:
            return
        # Deactivate previous game if it's different and active
        if self.active_game_idx is not None and self.active_game_idx != idx:
            self._deactivate_game(self.active_game_idx)
        # Toggle the clicked game
        if self.active_game_idx == idx:
            self._deactivate_game(idx)          # click again = deactivate
        else:
            self._activate_game(idx)            # activate this one
        # Full refresh, not just the colours: the asterisk lives in the row
        # text, so it has to be reinserted.
        self._refresh_game_list()

    # ---- Cheat tree ------------------------------------------------------
    GLYPH = {'on': "\u2611", 'off': "\u2610", 'partial': "\u25EA",
             'empty': "\u2610"}

    def _clear_cheat_view(self):
        self.cheat_tree.delete(*self.cheat_tree.get_children())
        self._tree_items.clear()
        self._tree_parent.clear()

    def _current_section(self):
        return self.section_var.get() if hasattr(self, 'section_var') \
            else "cheats"

    def _current_cheats(self):
        """
        The node list the tree is showing, or None.

        Everything that edits the tree goes through here, so adding, importing,
        grouping, pasting and deleting all land in whichever section is on
        screen without any of those routines knowing sections exist.
        """
        idx = self.selected_game_idx
        if idx is None or idx >= len(self.games):
            return None
        return game_section(self.games[idx], self._current_section())

    def _on_section_change(self, event=None):
        try:
            key = list(self._section_pages)[self.section_tabs.index("current")]
        except Exception:                                  # noqa: BLE001
            key = "cheats"
        if key == self.section_var.get():
            return
        self.section_var.set(key)
        self.section_heading.config(
            text="Patches" if key == "patches" else "Cheats")
        self._display_cheats(self.selected_game_idx)

    def _node_label(self, node):
        if is_group(node):
            g, c = count_tree(node['children'])
            suffix = f"  ({c} cheat{'s' if c != 1 else ''}" + \
                     (f", {g} group{'s' if g != 1 else ''})" if g else ")")
            return f"{self.GLYPH[group_state(node)]} {node['name']}{suffix}"
        # The author used to be appended here; it lives in the panel above the
        # tree now, so the row stays readable at any name length.
        return f"{self.GLYPH['on' if node.get('enabled') else 'off']} {node['name']}"

    def _display_cheats(self, idx):
        self._capture_open_state()      # before the item ids are thrown away
        self._clear_cheat_view()
        self._clear_meta_boxes()
        self._set_game_id(None if idx is None or idx >= len(self.games)
                          else self.games[idx])
        if idx is None or idx >= len(self.games):
            return
        self._insert_nodes("", game_section(self.games[idx],
                                           self._current_section()))

    def _insert_nodes(self, parent_item, nodes):
        for node in self._ordered(nodes):
            item = self.cheat_tree.insert(
                parent_item, "end", text=self._node_label(node),
                open=bool(node.get('expanded', True)) if is_group(node) else False,
                tags=("group",) if is_group(node)
                     else ("on",) if node.get('enabled') else ("cheat",))
            self._tree_items[item] = node
            self._tree_parent[item] = nodes
            if is_group(node):
                self._insert_nodes(item, node['children'])

    def _refresh_item(self, item):
        """Repaint one row and every ancestor, whose partial state may change."""
        node = self._tree_items.get(item)
        if node is None:
            return
        self.cheat_tree.item(
            item, text=self._node_label(node),
            tags=("group",) if is_group(node)
                 else ("on",) if node.get('enabled') else ("cheat",))
        parent = self.cheat_tree.parent(item)
        if parent:
            self._refresh_item(parent)

    def _refresh_subtree(self, item):
        self._refresh_item(item)
        for child in self.cheat_tree.get_children(item):
            self._refresh_subtree(child)

    def _on_tree_select(self, event=None):
        """Fill the Author / Description panels for the selected cheat."""
        picked = self._selected_nodes()
        if len(picked) != 1 or is_group(picked[0][1]):
            self._clear_meta_boxes()
            return
        node = picked[0][1]
        self.author_box.config(text=node.get('author') or "\u2014",
                               fg="#E0E0E0" if node.get('author') else "#616161")
        self.desc_box.config(text=node.get('desc') or "\u2014",
                             fg="#E0E0E0" if node.get('desc') else "#616161")

    def _set_game_id(self, game):
        """
        Show "MS-100  (4D530064)" for the selected game.

        Kept read-only on purpose: this id is what the cheats/ and patches/
        filenames are keyed on, so an accidental edit here would quietly
        disconnect a game from its files.
        """
        box = getattr(self, 'gameid_box', None)
        if box is None:
            return
        if game:
            tid = (game.get('titleid') or '').strip()
            # The online whitelist is keyed per title, so the engine needs to
            # know which game these cheats belong to. Set here because this
            # runs whenever the selection changes.
            self.cheat_engine.online_titleid = tid
            ser = (game.get('serial') or '').strip()
            if tid and not ser:
                ser = cheatfiles.serial_from_titleid(tid)
            if tid and ser:
                text = f"{ser}  ({tid})"
            elif tid:
                text = tid
            else:
                text = "\u2014  (no title id)"
        else:
            text = "\u2014"
        box.config(state="normal")
        self.gameid_var.set(text)
        box.config(state="readonly",
                   fg="#E0E0E0" if game and game.get('titleid') else "#616161")

    def _clear_meta_boxes(self):
        for box in (getattr(self, 'author_box', None),
                    getattr(self, 'desc_box', None)):
            if box is not None:
                box.config(text="\u2014", fg="#616161")

    def _restore_status(self):
        if self.mem.pid:
            self._status_connected()
        else:
            self.status_label.config(text="Waiting for Xemu...", fg="#FF9800")

    def _capture_open_state(self):
        """
        Copy what the tree is CURRENTLY showing back onto the nodes.

        Every rebuild reinserts groups with open=node['expanded'], so if that
        flag has drifted from what is on screen, the rebuild collapses groups
        the user had open - which is what renaming a cheat inside a group did.
        Snapshotting immediately before a rebuild makes the result depend on
        the visible state rather than on whether the <<TreeviewOpen>> handler
        happened to have run, and in the right order, beforehand.
        """
        for item, node in self._tree_items.items():
            if not is_group(node):
                continue
            try:
                node['expanded'] = bool(self.cheat_tree.item(item, "open"))
            except Exception:
                pass

    def _on_tree_open_close(self, event=None):
        """Remember expansion state so it survives a save/reload."""
        # after_idle: on a real expander click Tk can deliver the virtual event
        # before the widget's own open flag settles, so reading it synchronously
        # can record the state the group was in a moment ago.
        self.after_idle(self._sync_open_state)

    def _sync_open_state(self):
        self._capture_open_state()
        self._save_autosave()

    def _text_start(self, item, y):
        """
        The x where this row's label actually begins.

        bbox(item)[0] is the start of the ROW, which is the indent and the
        expander arrow - not the label. Measuring the toggle zone from there
        put it entirely inside the indent, so clicking the checkbox did
        nothing, and nested rows were further off with every level. Probing for
        the first x that reports the "text" element finds the real position
        whatever the theme's indent and depth happen to be.
        """
        bb = self.cheat_tree.bbox(item)
        if not bb:
            return None
        x0, _, w, _ = bb
        for x in range(int(x0), int(x0 + w)):
            if self.cheat_tree.identify_element(x, y) == "text":
                return x
        return None

    def _on_tree_click(self, event):
        """Clicking the checkbox glyph toggles; clicking elsewhere selects."""
        item = self.cheat_tree.identify_row(event.y)
        if not item:
            return
        if self.cheat_tree.identify_element(event.x, event.y) \
                in ("Treeitem.indicator", "indicator"):
            return              # the expander arrow belongs to the tree
        start = self._text_start(item, event.y)
        if start is None:
            return
        if start <= event.x <= start + self._glyph_w:
            self._toggle_item(item)
            return "break"

    def _on_tree_double_click(self, event):
        item = self.cheat_tree.identify_row(event.y)
        if not item:
            return
        node = self._tree_items.get(item)
        if node is None:
            return
        # Editing on double-click was too easy to trigger by accident while
        # clicking around the list. Edit lives on the right-click menu (and the
        # Edit button) only; a double-click on a group still expands it, and on
        # a cheat it now does nothing.
        return None if is_group(node) else "break"

    def _on_tree_space(self, event):
        for item in self.cheat_tree.selection():
            self._toggle_item(item)
        return "break"

    def _toggle_item(self, item):
        node = self._tree_items.get(item)
        if node is None:
            return
        if is_group(node):
            # Half-on groups turn fully on, matching how PJ64 behaves.
            value = group_state(node) != 'on'
            changed = set_subtree_enabled(node, value)
            self._refresh_subtree(item)
            parent = self.cheat_tree.parent(item)
            if parent:
                self._refresh_item(parent)
        else:
            node['enabled'] = not node.get('enabled', False)
            changed = [node] if node['enabled'] else []
            self._refresh_item(item)
        for c in changed:
            # A newly enabled increment code must fire once more.
            self.cheat_engine._increment_applied[c.get('_bid', 0)] = False
        self._rebuild_active_blocks()
        self._save_autosave()

    def _on_tree_menu(self, event):
        item = self.cheat_tree.identify_row(event.y)
        # Only reselect when the click landed OUTSIDE the current selection.
        # An unconditional selection_set() here is what threw away a shift- or
        # ctrl-built multi-row selection the moment you right-clicked it.
        if item and item not in self.cheat_tree.selection():
            self.cheat_tree.selection_set(item)
        node = self._tree_items.get(item) if item else None
        picked = self._selected_nodes()
        n_sel = len(picked)
        many = f" ({n_sel} selected)" if n_sel > 1 else ""
        in_group = any(p is not None and p is not self._current_cheats()
                       for _, _, p in picked)
        menu = tk.Menu(self, tearoff=0, bg="#212121", fg="#E0E0E0",
                       activebackground="#37474F", activeforeground="#FFFFFF")
        menu.add_command(label="Enable / Disable  (Space)",
                         command=lambda: item and self._toggle_item(item),
                         state="normal" if item else "disabled")
        menu.add_separator()
        menu.add_command(label="Add Cheat here", command=self._add_cheat)
        menu.add_command(label="Add Group here", command=self._add_group)
        menu.add_separator()
        menu.add_command(label="Edit", command=self._edit_selected,
                         state="normal" if node and n_sel == 1 else "disabled")
        menu.add_command(label="Rename", command=self._rename_selected,
                         state="normal" if node and n_sel == 1 else "disabled")
        menu.add_command(label=f"Copy{many}  (Ctrl+C)",
                         command=self._copy_selected,
                         state="normal" if node else "disabled")
        menu.add_command(label="Paste  (Ctrl+V)", command=self._paste_code)
        menu.add_command(label=f"Delete{many}", command=self._delete_selected,
                         state="normal" if node else "disabled")
        menu.add_separator()
        move = tk.Menu(menu, tearoff=0, bg="#212121", fg="#E0E0E0",
                       activebackground="#37474F", activeforeground="#FFFFFF")
        move.add_command(label=self.TOP_LEVEL,
                         command=self._move_selected_to_root)
        cheats = self._current_cheats()
        paths = group_paths(cheats) if cheats is not None else []
        if paths:
            move.add_separator()
            for path, lst in paths:
                move.add_command(
                    label=path,
                    command=lambda l=lst: self._move_selected_into(l))
        move.add_separator()
        move.add_command(label=self.NEW_GROUP,
                         command=lambda: self._move_selected_into(None))
        menu.add_cascade(label=f"Move to group{many}", menu=move,
                         state="normal" if node else "disabled")
        menu.add_command(label=f"Remove from group{many}",
                         command=self._move_selected_to_root,
                         state="normal" if in_group else "disabled")
        menu.add_command(label="Move out one level",
                         command=self._move_selected_up_one,
                         state="normal" if in_group else "disabled")
        menu.add_command(label="Sort this entry permanently (A-Z)",
                         command=self._sort_permanently)
        menu.add_separator()
        menu.add_command(label="Expand All",
                         command=lambda: self._set_all_open(True))
        menu.add_command(label="Collapse All",
                         command=lambda: self._set_all_open(False))
        # No grab_release() here. tk_popup takes a grab so the menu can see the
        # next click anywhere on screen and unpost itself; releasing it
        # immediately - as the usual try/finally snippet does - leaves the menu
        # posted with nothing listening, so clicking outside never dismissed it.
        menu.bind("<FocusOut>", lambda e, m=menu: m.unpost())
        menu.bind("<Escape>", lambda e, m=menu: m.unpost())
        popup_menu(menu, event.x_root, event.y_root)
        return "break"

    def _sort_permanently(self):
        """
        Rewrite the stored order alphabetically.

        The Sort control only changes the view. This is the one action that
        commits it, for when you want the file itself tidied - it cannot be
        undone by switching back to "Order added".
        """
        cheats = self._current_cheats()
        if cheats is None:
            return
        if not messagebox.askyesno(
                "Sort permanently",
                "Reorder the stored cheat list alphabetically?\n\n"
                "This overwrites the order they were added in, which the "
                "\"Order added\" view mode relies on."):
            return
        sort_tree(cheats)
        self._display_cheats(self.selected_game_idx)
        self._save_autosave(immediate=True)

    def _set_all_open(self, opened):
        for item, node in self._tree_items.items():
            if is_group(node):
                self.cheat_tree.item(item, open=opened)
                node['expanded'] = opened
        self._save_autosave()

    # ---- Drag to reparent -------------------------------------------------
    def _on_drag_start(self, event):
        item = self.cheat_tree.identify_row(event.y)
        # Two different gestures share the left button, the same way a file
        # manager does it: dragging a row that is ALREADY selected moves the
        # selection, dragging one that is not sweeps out a new selection.
        self._drag = {'item': item, 'y': event.y, 'active': False,
                      'mode': 'move' if item in self.cheat_tree.selection()
                              else 'select',
                      'anchor': item}

    def _on_drag_motion(self, event):
        if not self._drag or not self._drag['item']:
            return
        if not self._drag['active']:
            if abs(event.y - self._drag['y']) < 6:
                return          # a click, not a drag
            self._drag['active'] = True
        target = self.cheat_tree.identify_row(event.y)

        if self._drag['mode'] == 'select':
            if target:
                self.cheat_tree.selection_set(
                    self._rows_between(self._drag['anchor'], target))
                self.cheat_tree.see(target)
            return "break"

        if target and target != self._drag['item']:
            self.cheat_tree.see(target)

    def _visible_rows(self):
        """Every currently displayed row, top to bottom."""
        rows = []
        def walk(parent):
            for child in self.cheat_tree.get_children(parent):
                rows.append(child)
                if self.cheat_tree.item(child, "open"):
                    walk(child)
        walk("")
        return rows

    def _rows_between(self, a, b):
        """The visible rows from `a` to `b` inclusive, in display order."""
        rows = self._visible_rows()
        try:
            i, j = rows.index(a), rows.index(b)
        except ValueError:
            return [b] if b else []
        if i > j:
            i, j = j, i
        return rows[i:j + 1]

    def _on_drag_drop(self, event):
        drag = self._drag
        self._drag = None
        if not drag or not drag['active'] or not drag['item']:
            return
        if drag['mode'] == 'select':
            return "break"      # the sweep already set the selection
        src_item = drag['item']
        if self._tree_items.get(src_item) is None:
            return
        dst_item = self.cheat_tree.identify_row(event.y)
        if dst_item == src_item:
            return

        # Dropping onto a group puts the nodes inside it; onto a cheat puts
        # them beside that cheat; onto blank space sends them to the top level.
        if not dst_item:
            dst_list = self._current_cheats()
        else:
            dst_node = self._tree_items.get(dst_item)
            if dst_node is None:
                return
            dst_list = dst_node['children'] if is_group(dst_node) \
                else self._tree_parent.get(dst_item)
        if dst_list is None:
            return
        if dst_item:
            self.cheat_tree.item(dst_item, open=True)
        # Drag the whole selection, not just the row under the cursor - the
        # drag only enters move mode when it started on a selected row.
        self._move_selected_into(dst_list)

    @staticmethod
    def _list_within(node, lst):
        """True if `lst` is node's own child list or one nested below it."""
        if not is_group(node):
            return False
        if node['children'] is lst:
            return True
        return any(CheatManagerApp._list_within(child, lst)
                   for child in node['children'] if is_group(child))

    @staticmethod
    def _is_ancestor(node, candidate):
        """True if `candidate` is `node` itself or lives somewhere under it."""
        if node is candidate:
            return True
        if not is_group(node):
            return False
        return any(child is candidate or
                   (is_group(child) and CheatManagerApp._is_ancestor(child, candidate))
                   for child in node['children'])

    def _selected_node(self):
        sel = self.cheat_tree.selection()
        if not sel:
            return None, None
        item = sel[0]
        return item, self._tree_items.get(item)

    def _selected_nodes(self):
        """
        Every selected node as (item, node, parent_list), top-level first.

        Selections that sit inside another selected GROUP are dropped: moving a
        group already carries its contents, and moving both would either move
        the child twice or move it out of the group that is about to move.
        """
        picked = []
        for item in self.cheat_tree.selection():
            node = self._tree_items.get(item)
            if node is None:
                continue
            picked.append((item, node, self._tree_parent.get(item)))
        groups = [n for _, n, _ in picked if is_group(n)]
        out = []
        for item, node, parent in picked:
            if any(g is not node and self._is_ancestor(g, node)
                   for g in groups):
                continue
            out.append((item, node, parent))
        return out

    def _reselect(self, nodes):
        """Re-highlight `nodes` after a rebuild handed out fresh item ids."""
        wanted = {id(n) for n in nodes}
        items = [i for i, n in self._tree_items.items() if id(n) in wanted]
        if items:
            self.cheat_tree.selection_set(items)
            self.cheat_tree.see(items[0])

    def _insertion_list(self):
        """Where a new node should go: inside the selected group, else beside."""
        cheats = self._current_cheats()
        if cheats is None:
            return None
        item, node = self._selected_node()
        if node is None:
            return cheats
        if is_group(node):
            return node['children']
        return self._tree_parent.get(item, cheats)

    def _report_asm_route(self):
        """
        Remind the user that a code patch may need a save state to show up.

        xemu's JIT only drops a translated block when the write goes through
        its own memory path. A write from this process into its RAM is
        invisible to it, so a patched instruction keeps running in its old
        translated form until something flushes the cache - loading a save
        state does. That is a property of the emulator, not something this tool
        can work around, so the honest thing is to say it rather than let an
        applied patch look broken.

        Only when an [ASM] cheat is actually enabled, and only once per change.
        """
        eng = self.cheat_engine
        names = [b.get('name') for b in self._active_blocks
                 if eng.is_asm_name(b.get('name'))]
        if not names:
            self._last_asm_note = None
            return
        note = f"{len(names)} code patch(es) applied"
        if note == getattr(self, '_last_asm_note', None):
            return
        self._last_asm_note = note
        self.status_label.config(
            text=f"[ASM] {note} - if the effect does not appear, load a save "
                 f"state (xemu caches translated code)", fg="#FF9800")
        self.after(6000, self._restore_status)

    def _restore_disabled_asm(self):
        """
        Put back the original code for every [ASM] cheat that is now off.

        Driven from _rebuild_active_blocks() rather than from the checkbox
        handler, so it covers every route to disabling something: the tick box,
        the space bar, the right-click menu, a group toggle, Disable All, and
        switching games. Anything that changes what is enabled ends up here.
        """
        eng = self.cheat_engine
        if not eng.asm_orig:
            return 0, 0
        live = set()
        for game in self.games:
            active = game.get('active', False)
            for blk in all_game_nodes(game):
                # `_asm` covers the patches section; the name suffix still
                # covers a cheat the user tagged by hand. Checking only the
                # name here would leave a disabled patch journalled forever
                # and never write its original bytes back.
                if active and blk.get('enabled') and \
                        (blk.get('_asm') or eng.is_asm_name(blk.get('name'))):
                    live.add(blk.get('_bid', 0))
        total_r = total_f = 0
        for bid in {k[0] for k in eng.asm_orig} - live:
            r, f = eng.restore_asm(bid)
            total_r += r
            total_f += f
        if total_r or total_f:
            msg = f"[ASM] restored {total_r} original byte range(s)"
            if total_f:
                msg += (f"; {total_f} could not be restored - those addresses "
                        f"are no longer mapped")
            self.status_label.config(text=msg,
                                     fg="#4CAF50" if not total_f else "#FF9800")
            self.after(4000, self._restore_status)
        return total_r, total_f

    def _rebuild_active_blocks(self):
        """Refresh the list the freeze thread reads."""
        idx = self.active_game_idx
        if idx is None or idx >= len(self.games) or \
                not self.games[idx].get('active', False):
            self._active_blocks = ()
            self._restore_disabled_asm()
            return
        # Both sections run: a patch is applied by the same freeze loop as a
        # cheat, and a widescreen patch that stopped being reapplied the moment
        # you switched to the Cheats tab would be a bizarre thing to debug.
        blocks = []
        for section in SECTIONS:
            blocks.extend(enabled_cheats(self.games[idx].get(section, []) or []))
        self._active_blocks = tuple(blocks)
        # After the freeze list is narrowed, never before: restoring first
        # would race a tick already in flight, which would rewrite the patch
        # microseconds after it was undone.
        self._restore_disabled_asm()
        self._report_asm_route()
        if self._active_blocks:
            self._ensure_freeze_thread()

    def _add_game(self):
        name = simpledialog.askstring("Add Game", "Game name:", parent=self)
        if not name: return
        # Ask if user wants to load a cheat file now
        load_file = messagebox.askyesno("Add Game", "Do you want to load a cheat file now?")
        path = ""
        cheats = []
        if load_file:
            path = filedialog.askopenfilename(title="Select Cheat File",
                                              filetypes=[("Cheat files", "*.cht"), ("All files", "*.*")])
            if path:
                try:
                    cheats = self.cheat_engine.parse_file(path)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to parse: {e}")
                    return

        self.games.append({"name": name, "path": path, "cheats": cheats, "active": False})
        self._refresh_game_list()
        self._save_autosave(immediate=True)

    def _remove_game(self):
        sel = self.game_listbox.curselection()
        if not sel: return
        idx = self._row_to_game_index(sel[0])
        if idx is None:
            return
        if self.active_game_idx == idx:
            self._deactivate_game(idx)
        del self.games[idx]
        self._refresh_game_list()
        self.selected_game_idx = None
        self._clear_cheat_view()
        self._rebuild_active_blocks()
        self._save_autosave(immediate=True)

    # ---- Cheat + group editing -------------------------------------------
    NEW_GROUP = "\u2795  New group\u2026"
    TOP_LEVEL = "(top level)"

    def _copy_if_tree_focused(self, event=None):
        if self.focus_get() is self.cheat_tree:
            return self._copy_selected()

    def _paste_if_tree_focused(self, event=None):
        w = self.focus_get()
        # Never hijack a text field: there, Ctrl+V means paste text.
        if isinstance(w, (tk.Entry, tk.Text)) or \
                isinstance(w, ttk.Entry):
            return None
        return self._paste_code()

    def _cheat_dialog(self, title, name="", codes=(), on_save=None,
                      desc="", author="", current_list=None):
        """
        Shared add/edit dialog.

        The old code tried to reuse _add_cheat() for editing by reaching into
        win.children['!button'] to re-point Save, gave up halfway, and left a
        bare `pass` behind - so editing a cheat silently did nothing while
        appending a duplicate. One dialog with an on_save callback removes the
        need for any of that.
        """
        win = tk.Toplevel(self)
        win.title(title)
        win.geometry("520x560")
        win.configure(bg="#212121")
        win.transient(self)
        # grab_set() is deliberately NOT called here. A window cannot be
        # grabbed until the server has mapped it, and inside a double-click
        # handler it has not been yet - Tk raises "grab failed: window not
        # viewable", which aborted this function before a single widget was
        # created and left the empty grey box you would then have to close by
        # hand. The grab is taken at the end, once there is something to show.

        tk.Label(win, text="Cheat Name:", fg="#FFFFFF", bg="#212121",
                 font=("Helvetica",10)).pack(pady=(10,0))
        name_entry = tk.Entry(win, font=("Helvetica",10), bg="#424242",
                              fg="#FFFFFF", insertbackground="white", width=40)
        name_entry.pack(pady=5, padx=20)
        name_entry.insert(0, name)
        name_entry.focus_set()

        tk.Label(win, text="Author:", fg="#FFFFFF", bg="#212121",
                 font=("Helvetica",10)).pack(pady=(6,0))
        author_entry = tk.Entry(win, font=("Helvetica",10), bg="#424242",
                                fg="#FFFFFF", insertbackground="white", width=40)
        author_entry.pack(pady=3, padx=20)
        author_entry.insert(0, author)

        tk.Label(win, text="Description:", fg="#FFFFFF", bg="#212121",
                 font=("Helvetica",10)).pack(pady=(6,0))
        # highlightthickness=0: with the default ring, focusing this box drew
        # a border right around it that reads as the whole field being
        # selected rather than a caret sitting in it.
        desc_text = tk.Text(win, font=("Helvetica",9), bg="#2A2A2A",
                            fg="#E0E0E0", insertbackground="white",
                            height=3, width=50, wrap="word",
                            highlightthickness=0, bd=1, relief="flat",
                            selectbackground="#37474F")
        # Tk hands a newly focused Text the X selection in some window
        # managers, which shows up as every line highlighted. Drop it.
        desc_text.bind("<FocusIn>",
                       lambda e, w=desc_text: w.tag_remove("sel", "1.0", tk.END))
        desc_text.pack(pady=3, padx=20, fill="x")
        if desc:
            desc_text.insert("1.0", desc)

        # Group picker: every existing group, plus an inline "New group" that
        # creates one on save - so a cheat can be filed without having to make
        # the group first and drag it over afterwards.
        cheats_root = self._current_cheats()
        paths = group_paths(cheats_root) if cheats_root is not None else []
        choices = [self.TOP_LEVEL] + [p for p, _ in paths] + [self.NEW_GROUP]
        current = self.TOP_LEVEL
        for pth, lst in paths:
            if current_list is not None and lst is current_list:
                current = pth
                break
        tk.Label(win, text="Group:", fg="#FFFFFF", bg="#212121",
                 font=("Helvetica",10)).pack(pady=(6,0))
        group_var = tk.StringVar(value=current)
        group_menu = tk.OptionMenu(win, group_var, *choices)
        group_menu.config(font=("Helvetica",9), bg="#424242", fg="#E0E0E0",
                          highlightthickness=0, bd=0, activebackground="#616161")
        group_menu.pack(pady=3, padx=20)
        bind_wheel_cycle(group_menu, choices, group_var.get, group_var.set)

        tk.Label(win, text="Code Lines (one per line, format: AAAAAAAA VVVVVVVV):",
                 fg="#FFFFFF", bg="#212121", font=("Helvetica",10)).pack(pady=(10,0))
        code_text = tk.Text(win, font=("Courier",10), bg="#151515", fg="#00FF00",
                            insertbackground="white", height=12, width=50,
                            undo=True)
        code_text.pack(pady=5, padx=20, fill="both", expand=True)
        if codes:
            code_text.insert("1.0",
                             "\n".join(f"{c:08X} {v:08X}" for c, v in codes))

        def save():
            new_name = name_entry.get().strip()
            raw = code_text.get("1.0", tk.END).strip()
            if not new_name:
                messagebox.showerror("Error", "Name cannot be empty.", parent=win)
                return
            lines = self.cheat_engine.parse_raw_code_text(raw)
            if not lines:
                messagebox.showerror("Error", "No valid code lines found.",
                                     parent=win)
                return
            target = self._resolve_group_choice(group_var.get(), win)
            if target is None:
                return                      # cancelled the new-group prompt
            meta = {'desc': desc_text.get("1.0", tk.END).strip(),
                    'author': author_entry.get().strip()}
            win.destroy()
            if on_save:
                on_save(new_name, lines, target, meta)

        btns = tk.Frame(win, bg="#212121")
        btns.pack(pady=10)
        tk.Button(btns, text="Save", command=save, font=("Helvetica",10,"bold"),
                  bg="#4CAF50", fg="white", relief="flat",
                  padx=15, pady=5).pack(side="left", padx=5)
        tk.Button(btns, text="Cancel", command=win.destroy,
                  font=("Helvetica",10), bg="#f44336", fg="white",
                  relief="flat", padx=15, pady=5).pack(side="left", padx=5)
        win.bind("<Escape>", lambda e: win.destroy())
        self._grab_when_viewable(win)
        return win

    def _grab_when_viewable(self, win, tries=20):
        """
        Make `win` modal as soon as the window manager has mapped it.

        Retrying beats wait_visibility() here: wait_visibility blocks the event
        loop, and if the window never maps - no WM running, or the dialog is
        closed first - it blocks forever. Failing to grab is also not worth an
        exception; the dialog still works, it just is not modal.
        """
        try:
            if not win.winfo_exists():
                return
            if win.winfo_viewable():
                win.grab_set()
                return
        except tk.TclError:
            pass
        if tries > 0:
            win.after(25, lambda: self._grab_when_viewable(win, tries - 1))

    def _resolve_group_choice(self, choice, parent=None):
        """
        Turn a group-picker selection into the child list to file a cheat in.

        Returns None only if the user cancelled the new-group prompt, which the
        caller treats as "don't save yet" rather than "top level".
        """
        cheats = self._current_cheats()
        if cheats is None:
            return None
        if choice == self.NEW_GROUP:
            name = simpledialog.askstring("New Group", "Group name:",
                                          parent=parent or self)
            if not name or not name.strip():
                return None
            return group_child(cheats, name.strip())
        if choice == self.TOP_LEVEL:
            return cheats
        for path, lst in group_paths(cheats):
            if path == choice:
                return lst
        return cheats

    def _add_cheat(self):
        if self._current_cheats() is None:
            messagebox.showinfo("Add Cheat", "Please select a game first.")
            return

        def commit(name, lines, target, meta):
            target.append(make_cheat(name, lines, desc=meta['desc'],
                                     author=meta['author']))
            self._display_cheats(self.selected_game_idx)
            self._rebuild_active_blocks()
            self._save_autosave(immediate=True)

        # Pre-select whatever group is highlighted, so "Add Cheat" with a group
        # selected still files it there without touching the picker.
        self._cheat_dialog("Add Cheat", on_save=commit,
                           current_list=self._insertion_list())

    def _add_group(self):
        target = self._insertion_list()
        if target is None:
            messagebox.showinfo("Add Group", "Please select a game first.")
            return
        name = simpledialog.askstring("Add Group", "Group name:", parent=self)
        if not name or not name.strip():
            return
        target.append(make_group(name.strip()))
        self._display_cheats(self.selected_game_idx)
        self._save_autosave(immediate=True)

    def _edit_selected(self):
        item, node = self._selected_node()
        if node is None:
            return
        if is_group(node):
            self._rename_selected()
        else:
            self._edit_cheat(item)

    def _edit_cheat(self, item):
        node = self._tree_items.get(item)
        if node is None or is_group(node):
            return
        parent_list = self._tree_parent.get(item)

        def commit(name, lines, target, meta):
            node['name'] = name
            node['codes'] = lines
            node['desc'] = meta['desc']
            node['author'] = meta['author']
            # Codes changed, so a one-shot increment should run again.
            self.cheat_engine._increment_applied[node.get('_bid', 0)] = False
            if target is not None and parent_list is not None \
                    and target is not parent_list:
                try:
                    parent_list.remove(node)
                except ValueError:
                    pass
                target.append(node)
            self._display_cheats(self.selected_game_idx)
            self._rebuild_active_blocks()
            self._save_autosave(immediate=True)

        self._cheat_dialog("Edit Cheat", node['name'], node['codes'], commit,
                           desc=node.get('desc', ""),
                           author=node.get('author', ""),
                           current_list=parent_list)

    def _copy_selected(self, event=None):
        """
        Put the selected cheat's codes on the clipboard.

        A single cheat copies as bare code lines, ready to paste into another
        trainer or a forum post. A group copies as .cht blocks with full
        Weapons\\Ammo\\Name paths, so pasting the result into a file and
        loading it rebuilds the same nesting.
        """
        picked = self._selected_nodes()
        if not picked:
            return
        if len(picked) > 1:
            # Multiple rows copy as blocks so groups and metadata survive; a
            # single cheat still copies as bare lines, which is what you want
            # when pasting one code somewhere else.
            nodes = [n for _, n, _ in picked]
            text = "\n".join(self._cht_blocks(nodes))
            _, c = count_tree(nodes)
            self.clipboard_clear()
            self.clipboard_append(text)
            self.status_label.config(
                text=f"Copied {c} cheat{'s' if c != 1 else ''}", fg="#4CAF50")
            self.after(2500, self._restore_status)
            return
        item, node, _ = picked[0]
        if is_group(node):
            text = "\n".join(self._cht_blocks(node['children'], node['name']))
            label = f"{node['name']} ({count_tree(node['children'])[1]} cheats)"
        else:
            head = ""
            if node.get('author'):
                head += f"; Author: {node['author']}\n"
            if node.get('desc'):
                head += "".join(f"; {l}\n" for l in node['desc'].splitlines())
            text = head + "\n".join(f"{c:08X} {v:08X}" for c, v in node['codes'])
            label = node['name']
        if not text:
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self.status_label.config(text=f"Copied: {label}", fg="#4CAF50")
        self.after(2500, self._restore_status)

    def _paste_code(self, event=None):
        """
        Create cheats from whatever is on the clipboard.

        Two shapes are accepted, which between them cover copying from this
        trainer, from a .cht file, or from a forum post:

          * full blocks - [Name] { ... }, group paths and ; Author: comments
            included - which rebuild their own nesting under the target group;
          * bare "AAAAAAAA VVVVVVVV" lines, which become one cheat and prompt
            for a name.
        """
        if self._current_cheats() is None:
            messagebox.showinfo("Paste", "Please select a game first.")
            return "break"
        try:
            raw = self.clipboard_get()
        except tk.TclError:
            raw = ""
        if not raw.strip():
            messagebox.showinfo("Paste", "The clipboard is empty.")
            return "break"

        target = self._insertion_list()
        if target is None:
            return "break"

        if "[" in raw and "{" in raw:
            tree = self.cheat_engine.parse_text(raw)
            if not tree:
                messagebox.showerror(
                    "Paste",
                    "No valid cheat blocks found on the clipboard.")
                return "break"
            self._merge_into(target, tree)
            _, n = count_tree(tree)
            label = f"{n} cheat{'s' if n != 1 else ''}"
        else:
            lines = self.cheat_engine.parse_raw_code_text(raw)
            if not lines:
                messagebox.showerror(
                    "Paste",
                    "The clipboard holds no lines in AAAAAAAA VVVVVVVV form.")
                return "break"
            name = simpledialog.askstring(
                "Paste", "Name for the pasted cheat:", parent=self)
            if not name or not name.strip():
                return "break"
            target.append(make_cheat(name.strip(), lines))
            label = name.strip()

        self._display_cheats(self.selected_game_idx)
        self._rebuild_active_blocks()
        self._save_autosave(immediate=True)
        self.status_label.config(text=f"Pasted: {label}", fg="#4CAF50")
        self.after(2500, self._restore_status)
        return "break"

    def _merge_into(self, target, nodes):
        """
        Graft parsed nodes onto `target`, merging groups by name.

        Pasting Weapons\\Ammo twice should land in the existing Ammo group
        rather than creating a second one beside it.
        """
        for node in nodes:
            if is_group(node):
                self._merge_into(group_child(target, node['name']),
                                 node['children'])
            else:
                target.append(node)

    def _cht_blocks(self, nodes, prefix=""):
        out = []
        for node in nodes:
            path = f"{prefix}\\{node['name']}" if prefix else node['name']
            if is_group(node):
                out.extend(self._cht_blocks(node['children'], path))
            else:
                body = "\n".join(f"  {c:08X} {v:08X}" for c, v in node['codes'])
                head = ""
                if node.get('author'):
                    head += f"; Author: {node['author']}\n"
                if node.get('desc'):
                    head += "".join(f"; {line}\n"
                                    for line in node['desc'].splitlines())
                out.append(f"{head}[{path}] {{\n{body}\n}}")
        return out

    def _rename_selected(self):
        item, node = self._selected_node()
        if node is None:
            return
        name = simpledialog.askstring("Rename", "New name:", parent=self,
                                      initialvalue=node['name'])
        if not name or not name.strip():
            return
        node['name'] = name.strip()
        self._display_cheats(self.selected_game_idx)
        self._save_autosave(immediate=True)

    def _move_selected_to_root(self):
        """Take the selection out of its group, back to the main cheat list."""
        cheats = self._current_cheats()
        if cheats is None:
            return
        self._move_selected_into(cheats)

    def _move_selected_up_one(self):
        """
        Move the selection out by a single level.

        Distinct from "move to the main list": pulling a cheat out of
        Weapons / Ammo usually means putting it in Weapons, not at the top.
        """
        picked = self._selected_nodes()
        cheats = self._current_cheats()
        if not picked or cheats is None:
            return
        moved = []
        for item, node, src in picked:
            if src is None or src is cheats:
                continue                      # already at the top level
            grandparent_item = self.cheat_tree.parent(
                self.cheat_tree.parent(item))
            dst = cheats if not grandparent_item else \
                self._tree_items[grandparent_item]['children']
            if dst is src:
                continue
            try:
                src.remove(node)
            except ValueError:
                continue
            dst.append(node)
            moved.append(node)
        if not moved:
            return
        self._display_cheats(self.selected_game_idx)
        self._reselect(moved)
        self._rebuild_active_blocks()
        self._save_autosave(immediate=True)

    def _move_selected_into(self, dst_list):
        """
        Move every selected node into `dst_list`; None means make a new group.

        Selecting a run of cheats and filing them in one go is the normal case,
        so this works on the whole selection rather than just the first row.
        """
        picked = self._selected_nodes()
        cheats = self._current_cheats()
        if not picked or cheats is None:
            return
        if dst_list is None:
            name = simpledialog.askstring("New Group", "Group name:", parent=self)
            if not name or not name.strip():
                return
            dst_list = group_child(cheats, name.strip())

        blocked, moved = [], []
        for item, node, src in picked:
            if is_group(node) and self._list_within(node, dst_list):
                blocked.append(node['name'])
                continue
            if src is None or src is dst_list:
                continue
            try:
                src.remove(node)
            except ValueError:
                continue
            dst_list.append(node)
            moved.append(node)

        if blocked:
            messagebox.showinfo(
                "Move", "A group cannot be moved inside itself:\n  "
                + "\n  ".join(blocked))
        if not moved:
            return
        self._display_cheats(self.selected_game_idx)
        self._reselect(moved)
        self._rebuild_active_blocks()
        self._save_autosave(immediate=True)
        self.status_label.config(
            text=f"Moved {len(moved)} item{'s' if len(moved) != 1 else ''}",
            fg="#4CAF50")
        self.after(2500, self._restore_status)

    def _move_to_group_dialog(self):
        """Toolbar entry point: pick a destination group for the selection."""
        picked = self._selected_nodes()
        if not picked:
            messagebox.showinfo("Group", "Select one or more cheats first.")
            return
        node = picked[0][1]
        cheats = self._current_cheats()
        choices = [self.TOP_LEVEL] + [p for p, _ in group_paths(cheats)] \
                  + [self.NEW_GROUP]
        win = tk.Toplevel(self)
        win.title("Move to Group")
        win.configure(bg="#212121")
        win.transient(self)
        what = node['name'] if len(picked) == 1 \
            else f"{len(picked)} selected items"
        tk.Label(win, text=f"Move {what} into:", fg="#FFFFFF",
                 bg="#212121", font=("Helvetica",10)).pack(padx=20, pady=(14,6))
        var = tk.StringVar(value=self.TOP_LEVEL)
        om = tk.OptionMenu(win, var, *choices)
        om.config(font=("Helvetica",9), bg="#424242", fg="#E0E0E0",
                  highlightthickness=0, bd=0, activebackground="#616161")
        om.pack(padx=20, pady=4)
        bind_wheel_cycle(om, choices, var.get, var.set)

        def go():
            choice = var.get()
            win.destroy()
            if choice == self.NEW_GROUP:
                self._move_selected_into(None)
            elif choice == self.TOP_LEVEL:
                self._move_selected_to_root()
            else:
                for path, lst in group_paths(self._current_cheats()):
                    if path == choice:
                        self._move_selected_into(lst)
                        return

        btns = tk.Frame(win, bg="#212121"); btns.pack(pady=12)
        tk.Button(btns, text="Move", command=go, bg="#4CAF50", fg="white",
                  font=("Helvetica",10,"bold"), relief="flat",
                  padx=14, pady=4).pack(side="left", padx=5)
        tk.Button(btns, text="Cancel", command=win.destroy, bg="#f44336",
                  fg="white", font=("Helvetica",10), relief="flat",
                  padx=14, pady=4).pack(side="left", padx=5)
        win.bind("<Escape>", lambda e: win.destroy())
        self._grab_when_viewable(win)

    def _delete_selected(self):
        picked = self._selected_nodes()
        if not picked:
            return
        groups = [n for _, n, _ in picked if is_group(n)]
        cheats_hit = sum(len(list(walk_cheats([n]))) if is_group(n) else 1
                         for _, n, _ in picked)
        if groups or len(picked) > 1:
            what = f"{len(picked)} selected item" \
                   f"{'s' if len(picked) != 1 else ''}"
            if not messagebox.askyesno(
                    "Delete",
                    f"Delete {what}?\n\n"
                    f"{cheats_hit} cheat{'s' if cheats_hit != 1 else ''} "
                    "will be removed"
                    + (", including everything inside the selected groups."
                       if groups else ".")):
                return
        removed = 0
        for item, node, src in picked:
            if src is None:
                continue
            try:
                src.remove(node)
                removed += 1
            except ValueError:
                continue
        if not removed:
            return
        self._display_cheats(self.selected_game_idx)
        self._rebuild_active_blocks()
        self._save_autosave(immediate=True)

    def _reload_cheats(self):
        if self.selected_game_idx is None:
            return
        game = self.games[self.selected_game_idx]
        if not game.get('path'):
            messagebox.showinfo("Reload", "No cheat file associated with this game.")
            return
        try:
            tree = self.cheat_engine.parse_file(game['path'])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to reload: {e}")
            return
        game[self._current_section()] = tree
        self._display_cheats(self.selected_game_idx)
        self._rebuild_active_blocks()
        self._save_autosave(immediate=True)

    def _set_all(self, value):
        """Enable or disable everything, or just the selected subtree."""
        cheats = self._current_cheats()
        if cheats is None:
            return
        item, node = self._selected_node()
        if node is not None and is_group(node):
            changed = set_subtree_enabled(node, value)
            self._refresh_subtree(item)
            parent = self.cheat_tree.parent(item)
            if parent:
                self._refresh_item(parent)
        else:
            changed = []
            for c in walk_cheats(cheats):
                if c.get('enabled') != value:
                    c['enabled'] = value
                    changed.append(c)
            self._display_cheats(self.selected_game_idx)
        if value:
            for c in changed:
                self.cheat_engine._increment_applied[c.get('_bid', 0)] = False
        self._rebuild_active_blocks()
        self._save_autosave()

    def _enable_all(self):
        self._set_all(True)

    def _disable_all(self):
        self._set_all(False)

    def _save_autosave(self, immediate=False):
        """
        Write the database, coalescing bursts.

        Every toggle used to rewrite the entire INI synchronously on the GUI
        thread. That file is already ~70 KB here, and "Enable All" fired one
        full write per cheat, so the window locked up for the duration. A
        400 ms debounce turns any burst into a single write; structural edits
        pass immediate=True, and destroy() flushes whatever is still pending.
        """
        if immediate:
            if self._autosave_id is not None:
                try: self.after_cancel(self._autosave_id)
                except Exception: pass
                self._autosave_id = None
            self._write_config()
            return
        if self._autosave_id is not None:
            return
        self._autosave_id = self.after(400, self._flush_autosave)

    def _flush_autosave(self):
        self._autosave_id = None
        self._write_config()

    def _write_config(self):
        try:
            Config.save(self.games, self.geometry(), self.freeze_interval_ms,
                        self._sort_mode,
                        getattr(self.cheat_engine, 'gdb_enabled', True))
        except Exception as e:
            print(f"[!] Could not save database: {e}")

    # ---- Xemu connection ----
    def _check_connection(self):
        if getattr(self.mem, 'unsupported', False):
            # Say it once per tick in the status bar rather than looping on a
            # scan that cannot succeed on this OS.
            self.status_label.config(
                text=f"{self.mem.os_type} is not supported", fg="#f44336")
            self.after(5000, self._check_connection)
            return
        if self.mem.pid is None or not self.mem.is_alive():
            if self.mem.reconnect():
                self._status_connected()
            else:
                self.status_label.config(text="Waiting for Xemu...", fg="#FF9800")
        else:
            self._status_connected()
        self._update_gdb_status()
        self._update_online_status()
        self.after(2000, self._check_connection)

    def _update_online_status(self):
        """
        Say plainly when cheats are being held for online play.

        Silence here would look like the tool is broken: cheats enabled, values
        not changing, no explanation anywhere.
        """
        eng = self.cheat_engine
        if not getattr(eng, 'online_blocked_names', None):
            return
        n = len(eng.online_blocked_names)
        why = getattr(eng, 'online_block_reason', '')
        self.status_label.config(
            text=f"ONLINE - {n} cheat(s) held ({why})", fg="#f44336")
        eng.online_blocked_names.clear()

    def _update_gdb_status(self):
        """
        Show whether [ASM] patches are actually taking effect.

        A patch written the raw way lands in RAM and then does nothing, so
        "no stub" is worth saying out loud rather than letting the patch look
        applied while the game ignores it.
        """
        lbl = getattr(self, 'gdb_status_label', None)
        if lbl is None:
            return
        if not getattr(self.cheat_engine, 'gdb_enabled', True):
            lbl.config(text="raw writes", fg="#FF9800")
            return
        live, note = self.cheat_engine.gdb_status()
        if live:
            lbl.config(text="patched via gdbstub", fg="#4CAF50")
        elif self.cheat_engine.asm_orig:
            # Only nag once an [ASM] patch is actually in play.
            lbl.config(text="no gdbstub - type 'gdbserver' in xemu's Monitor",
                       fg="#f44336")
        else:
            lbl.config(text="", fg="#FF9800")

    def _status_connected(self):
        mb = self.mem.xbox_ram_size_mb
        machine = ("Retail" if mb == 64 else
                   "Debug / Dev Kit" if mb == 128 else
                   "Chihiro / Arcade" if mb == 256 else "Custom")
        self.status_label.config(
            text=f"Attached! Xbox {machine} ({mb}MB RAM) | PID: {self.mem.pid}",
            fg="#4CAF50")

    # ---- background cheat application ----

    def destroy(self):
        self._freeze_gen += 1          # retire the freeze thread
        self._active_blocks = ()
        # Undo [ASM] patches on the way out. Leaving a NOPed instruction in a
        # running game after the tool that made it has gone is the surprising
        # behaviour - and there would then be nothing left that knows what the
        # original bytes were.
        try:
            if self.cheat_engine.asm_orig:
                self.cheat_engine.restore_asm()
        except Exception:                                  # noqa: BLE001
            pass
        for game in self.games:
            for blk in all_game_nodes(game):
                self._stop_cheat_timer(blk)
        self._cheat_timers.clear()
        if self._autosave_id is not None:
            try: self.after_cancel(self._autosave_id)
            except Exception: pass
            self._autosave_id = None
        self._write_config()
        if platform.system() == "Windows" and self.mem.win_process_handle:
            ctypes.windll.kernel32.CloseHandle(self.mem.win_process_handle)
        super().destroy()

