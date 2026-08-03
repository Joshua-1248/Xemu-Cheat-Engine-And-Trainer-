"""Settings persistence.

Extracted verbatim from xemu_cheats_trainer.py.
"""
from .prelude import *  # noqa: F401,F403
import os, sys, time, struct, platform, threading, re, json, configparser
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from .tree_ops import normalise_tree, strip_tree  # noqa: F401
from . import cheatfiles  # noqa: F401


class Config:
    # Anchored to the package directory, not left as a bare relative name.
    # A relative name resolves against the current working directory, so
    # launching from a Windows shortcut, a .desktop entry, or any shell that
    # is not sitting in the install folder would silently start a SECOND,
    # empty database beside wherever that happened to be - and since
    # base_dir() derives cheats/ and patches/ from this path, the whole cheat
    # library would appear to have vanished.
    FILE = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "xemu_cheat_manager.ini")

    @staticmethod
    def _stem_of(game):
        """
        Filename stem for a game: SERIAL_TITLEID when the id is known, else the
        slug remembered from the file it was loaded out of.

        Games whose title id is not in the database still get files -- 43 of
        them -- so the folders remain a complete list rather than a partial one.
        """
        stem = (game.get('stem') or '').strip()
        if stem:
            return stem
        tid = (game.get('titleid') or '').strip()
        ser = (game.get('serial') or '').strip()
        if tid and not ser:
            ser = cheatfiles.serial_from_titleid(tid)
        if tid and ser:
            return cheatfiles.stem_for(ser, tid)
        return cheatfiles.slug_for(game.get('name') or '')

    @staticmethod
    def base_dir():
        """
        Directory the cheats/ and patches/ folders live in.

        Config.FILE is a relative name, so it resolves against the current
        working directory. Anchoring on its absolute path means the folders
        always sit beside the INI, whatever directory the app was launched
        from.
        """
        return os.path.dirname(os.path.abspath(Config.FILE))

    @staticmethod
    def load(games_list: list):
        """
        Build the game list from the cheats/ and patches/ folders.

        The folders are the database. A game exists because it has a file, not
        because it has an INI section. The INI is only [main] settings plus,
        for backwards compatibility, any game section that has no file yet --
        those still load exactly as they used to, so an old database opens
        unchanged.
        """
        config = configparser.ConfigParser()
        config.optionxform = str
        if os.path.exists(Config.FILE):
            config.read(Config.FILE, encoding='utf-8')

        base = Config.base_dir()
        by_name = {}

        # ---- games from files -------------------------------------------
        for stem, kinds in sorted(cheatfiles.discover(base).items()):
            name = titleid = serial = ''
            trees = {'cheats': [], 'patches': []}
            for kind, fp in sorted(kinds.items()):
                try:
                    tree, meta = cheatfiles.read_cheat_file(fp)
                except Exception:              # noqa: BLE001
                    continue
                trees[kind] = normalise_tree(tree)
                name = name or (meta.get('game') or '').strip()
                titleid = titleid or (meta.get('titleid') or '').strip()
                serial = serial or (meta.get('serial') or '').strip()
            if not name:
                name = stem
            if titleid and not serial:
                serial = cheatfiles.serial_from_titleid(titleid)
            by_name[name] = {'name': name, 'path': '',
                             'titleid': titleid, 'serial': serial,
                             'stem': stem,
                             'cheats': trees['cheats'],
                             'patches': trees['patches'], 'active': False}

        games_list.extend(by_name.values())
        Config._load_legacy_sections(config, games_list, by_name)
        return Config._apply_order(config, games_list)

    @staticmethod
    def _apply_order(config, games_list):
        main = config['main'] if 'main' in config else {}
        geometry = main.get('geometry', '')
        order = main.get('games', '').split(',') if 'games' in main else []
        if order:
            pos = {n: i for i, n in enumerate(order)}
            games_list.sort(key=lambda g: (pos.get(g['name'], len(pos)),
                                           g['name'].lower()))
        else:
            games_list.sort(key=lambda g: g['name'].lower())
        return geometry

    @staticmethod
    def _load_legacy_sections(config, games_list, by_name):
        """Game sections with no file yet - load them the old way."""
        # read each game section
        for section in config.sections():
            if section == 'main':
                continue
            # section name format: game:GameName
            if not section.startswith('game:'):
                continue
            name = section[5:]
            if name in by_name:
                continue                       # a file already provided it
            clean = cheatfiles.clean_title(name)
            if clean in by_name:
                continue
            game_data = {'name': name, 'path': config.get(section, 'path', fallback=''),
                         'cheats': [], 'patches': [], 'active': False}
            # cheat blocks are stored as JSON in key 'cheats'
            if config.has_option(section, 'cheats'):
                try:
                    cheats = json.loads(config.get(section, 'cheats'))
                    # Old databases are a flat list of cheat dicts; new ones may
                    # contain groups. normalise_tree handles both, since a node
                    # is a group only if it has a 'children' key.
                    game_data['cheats'] = normalise_tree(cheats)
                except Exception:
                    pass
            # Patches are a separate key. A database written before the section
            # existed simply has no 'patches' option, which reads back as an
            # empty list - so old files load unchanged rather than needing a
            # migration step.
            if config.has_option(section, 'patches'):
                try:
                    game_data['patches'] = normalise_tree(
                        json.loads(config.get(section, 'patches')))
                except Exception:
                    pass
            titleid = config.get(section, 'titleid', fallback='').strip()
            serial = config.get(section, 'serial', fallback='').strip()
            if titleid and not serial:
                serial = cheatfiles.serial_from_titleid(titleid)
            game_data['titleid'] = titleid
            game_data['serial'] = serial
            games_list.append(game_data)

        return

    @staticmethod
    def load_sort_mode():
        try:
            c = configparser.ConfigParser(); c.read(Config.FILE, encoding='utf-8')
            mode = c.get('main', 'sort_mode', fallback="Order added")
            return mode if mode in ("Order added", "Alphabetical") \
                else "Order added"
        except Exception:
            return "Order added"

    @staticmethod
    def load_freeze_ms():
        """Read the saved freeze interval, defaulting to 50 ms."""
        try:
            c = configparser.ConfigParser(); c.read(Config.FILE, encoding='utf-8')
            return max(1, min(c.getint('main', 'freeze_interval_ms',
                                       fallback=50), 5000))
        except Exception:
            return 50

    @staticmethod
    def load_gdb_patching():
        """
        Whether [ASM] patches are written through xemu's gdbstub.

        Defaults to on: a raw /proc write to code leaves QEMU's JIT running
        the block it already translated, so the patch does nothing.
        """
        try:
            c = configparser.ConfigParser(); c.read(Config.FILE, encoding='utf-8')
            return c.getboolean('main', 'gdb_patching', fallback=True)
        except Exception:
            return True

    @staticmethod
    def save(games_list: list, geometry: str, freeze_ms: int = 50,
             sort_mode: str = "Order added", gdb_patching: bool = True):
        config = configparser.ConfigParser()
        config['main'] = {
            'geometry': geometry,
            'freeze_interval_ms': str(int(freeze_ms)),
            'sort_mode': sort_mode,
            'gdb_patching': str(bool(gdb_patching)),
            'games': ','.join(g['name'] for g in games_list)
        }
        # ---- decide who writes which file, before writing anything -------
        #
        # Two game sections can share one title id (Doom 3 and Doom 3
        # Collector's Edition both report AV-032, for instance). Left alone
        # they would both target the same file and the last one would win.
        #
        # Resolve it up front rather than first-come-first-served: a section
        # holding actual cheats always beats an empty one. Deciding inside the
        # write loop meant an empty section could claim the path and delete a
        # file whose cheats belonged to the other section.
        plan = {}                       # path -> (game_name, kind, tree)
        for game in games_list:
            stem = Config._stem_of(game)
            if not stem:
                continue
            for kind in cheatfiles.KINDS:
                fp = cheatfiles.path_for_stem(Config.base_dir(), kind, stem)
                tree = game.get(kind, [])
                cur = plan.get(fp)
                if cur is None or (tree and not cur[2]):
                    plan[fp] = (game['name'], kind, tree)

        for game in games_list:
            section = f"game:{game['name']}"
            titleid = (game.get('titleid') or '').strip()
            serial = (game.get('serial') or '').strip()
            if titleid and not serial:
                serial = cheatfiles.serial_from_titleid(titleid)

            # Write the text files first. They are what gets loaded next time,
            # so they must land before the INI mirror is updated -- if the
            # process dies between the two, the INI is merely stale, not wrong.
            #
            # Enabled flags go out exactly as they are in memory. Nothing here
            # normalises, defaults or flips them.
            stem = Config._stem_of(game)
            if stem:
                for kind in cheatfiles.KINDS:
                    fp = cheatfiles.path_for_stem(Config.base_dir(), kind, stem)
                    if plan.get(fp, (None,))[0] != game['name']:
                        continue                 # another game owns it
                    tree = game.get(kind, [])
                    # Written even when empty. Every game keeps a cheats file
                    # and a patches file, so the folders stay a full list --
                    # deleting an emptied one would drop the game from the
                    # database entirely, since the folders now *are* the
                    # database.
                    try:
                        cheatfiles.write_cheat_file(
                            fp, cheatfiles.clean_title(game['name']),
                            serial, titleid, kind, game.get(kind, []))
                    except Exception:              # noqa: BLE001
                        pass

            # No game section is written. The folders are the database now:
            # every game has a cheats file and a patches file, so duplicating
            # all of it as JSON here would just create a second copy that can
            # drift. The INI holds settings only.
        # Write to a temp file and rename, so a crash mid-write cannot leave a
        # truncated database behind - this file is the only copy of the cheats.
        tmp = Config.FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            config.write(f)
        # Reclaim before the rename: os.replace keeps the temp file's inode,
        # so chowning afterwards would work too, but doing it here means the
        # file is never visible at its final name while still root-owned.
        xemu_privs.reclaim(tmp)
        os.replace(tmp, Config.FILE)

