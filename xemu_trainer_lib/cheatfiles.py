"""Cheat/patch file discovery, reading and writing.

Layout, beside the INI:

    xemu_cheat_manager.ini
    cheats/SERIAL_TITLEID.txt
    patches/SERIAL_TITLEID.txt

The two folders are scanned independently. A game may have a cheats file, a
patches file, both, or neither -- there is no single path pointing at one of
them.

The body is the .cht grammar the trainer already speaks. Everything that
grammar has no slot for rides on `//` lines, which parse_text skips:

    //game=      title
    //serial=    publisher serial
    //titleid=   hex title id
    //kind=      cheats | patches
    //enabled=   0/1, attached to the block directly below it
    //group=     group path, in tree order, so empty groups and ordering survive
    //collapsed= group path that should load collapsed

Enabled state is read from and written to the file verbatim. Loading a file
never turns a cheat on or off.
"""
import os
import re

from .prelude import *  # noqa: F401,F403
from .cheat_tree import make_cheat, make_group, group_child, is_group


CHEATS_DIR = "cheats"
PATCHES_DIR = "patches"
KINDS = ("cheats", "patches")


def clean_title(name):
    """
    "Halo 2 (USA)" -> "Halo 2".

    Region and language suffixes belong in the filename's title id, not in the
    human-readable title line. Stripping them here keeps //game= stable no
    matter which regional variant of a name the game list happens to use.
    """
    return re.sub(r'\s*\([^()]*\)', '', name or '').strip() or (name or '')


def stem_for(serial, titleid):
    """SERIAL_TITLEID, the PCSX2-pnach-style filename stem."""
    if not serial or not titleid:
        return ""
    return f"{serial}_{titleid}".upper().replace("_", "_")


def slug_for(name):
    """
    Filename stem for a game with no known title id.

    37 names in this database are simply not in the title id list and 6 more
    are second claimants on an id another game owns. A slug keeps them in the
    folders instead of dropping them.
    """
    s = re.sub(r'[^A-Za-z0-9]+', '_', clean_title(name)).strip('_')
    return s or 'unnamed'


def path_for_stem(base_dir, kind, stem):
    """Path of a file from an already-decided stem."""
    folder = CHEATS_DIR if kind == "cheats" else PATCHES_DIR
    return os.path.join(base_dir, folder, stem + ".txt")


def file_for(base_dir, kind, serial, titleid):
    """Absolute path of a game's file for one kind, or '' if not identifiable."""
    stem = stem_for(serial, titleid)
    if not stem:
        return ""
    folder = CHEATS_DIR if kind == "cheats" else PATCHES_DIR
    return os.path.join(base_dir, folder, stem + ".txt")


def serial_from_titleid(titleid):
    """
    4D530064 -> MS-100.

    The hex title id *is* the serial: two ASCII bytes for the publisher then a
    16-bit game number. Deriving it means a game only needs one of the two
    recorded, and a mismatch between them is detectable.
    """
    try:
        tid = int(str(titleid), 16)
    except (TypeError, ValueError):
        return ""
    a, b = (tid >> 24) & 0xFF, (tid >> 16) & 0xFF
    if not (0x20 <= a < 0x7F and 0x20 <= b < 0x7F):
        return ""
    return f"{chr(a)}{chr(b)}-{tid & 0xFFFF:03d}"


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------
_BLOCK = re.compile(r'((?:^[ \t]*;[^\n]*\n)*)'
                    r'\[([^\n]*)\]\s*\{\s*(.*?)\s*\}',
                    re.DOTALL | re.MULTILINE)


def _split_path(name):
    r"""
    Split a group path on unescaped backslash.

    Backslash alone is the separator here, NOT backslash-or-slash. One of the
    groups in this database is literally named "Driving/On-Rails" -- treating
    `/` as a separator silently turns that single group into two nested ones.
    A literal backslash in a name is written `\\`.

    (The legacy .cht importer still accepts `/` as a separator, which is a
    convenience for hand-written files. This format round-trips instead.)
    """
    parts, cur, i = [], [], 0
    while i < len(name):
        ch = name[i]
        if ch == '\\':
            if i + 1 < len(name) and name[i + 1] == '\\':
                cur.append('\\')
                i += 2
                continue
            parts.append(''.join(cur))
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    parts.append(''.join(cur))
    return [p.strip() for p in parts if p.strip()]


def _join_path(parts):
    r"""Inverse of _split_path: escape literal backslashes, join with `\`."""
    return '\\'.join(p.replace('\\', '\\\\') for p in parts)


def _ensure_group(root, parts, expanded=True):
    """Walk/create a group path, returning the deepest child list."""
    parent = root
    for comp in parts:
        found = None
        for node in parent:
            if is_group(node) and node['name'].lower() == comp.lower():
                found = node
                break
        if found is None:
            found = make_group(comp, expanded=expanded)
            parent.append(found)
        parent = found['children']
    return parent


def parse_cheat_text(content):
    """
    Parse a cheat file into (tree, meta).

    The file is replayed in document order: a //group line creates that group
    at the point it appears, a block appends a cheat. Because render writes
    groups and cheats interleaved in tree order, replaying reproduces the tree
    exactly -- sibling order, nesting, empty groups and all.

    //enabled attaches to the block below it, so moving a whole stanza by hand
    carries its state along.
    """
    meta = {'game': '', 'serial': '', 'titleid': '', 'kind': ''}
    for line in content.splitlines():
        s = line.strip()
        if not s.startswith('//'):
            continue
        key, _, val = s[2:].partition('=')
        key = key.strip().lower()
        if key in ('game', 'serial', 'titleid', 'kind'):
            meta[key] = val.strip()

    collapsed = {m.group(1).strip().lower() for m in
                 re.finditer(r'(?m)^\s*//collapsed=(.*)$', content)}

    root = []
    pending_enabled = None

    # One ordered pass over every directive and block.
    #
    # re.DOTALL is required for the code body, which spans lines. That makes
    # `.` match newlines everywhere, so the single-line directives must spell
    # out [^\n]* rather than use `.` -- otherwise //group=.* swallows the rest
    # of the file.
    scanner = re.compile(
        r'(?m)^[ \t]*//group=(?P<grp>[^\n]*)'
        r'|^[ \t]*//enabled=(?P<en>[^\n]*)'
        r'|(?P<head>(?:^[ \t]*;[^\n]*\n)*)'
        r'\[(?P<name>[^\n]*)\][ \t]*\{\s*(?P<body>.*?)\s*\}',
        re.DOTALL)

    for m in scanner.finditer(content):
        if m.group('grp') is not None:
            parts = _split_path(m.group('grp'))
            if parts:
                _ensure_group(root, parts,
                              expanded=m.group('grp').strip().lower()
                              not in collapsed)
            continue
        if m.group('en') is not None:
            pending_enabled = (m.group('en').strip() == '1')
            continue

        author, notes = "", []
        for raw in (m.group('head') or '').splitlines():
            line = raw.strip().lstrip(';').strip()
            if not line:
                continue
            low = line.lower()
            if low.startswith("author:"):
                author = line.split(":", 1)[1].strip()
            elif low.startswith(("desc:", "description:")):
                notes.append(line.split(":", 1)[1].strip())
            else:
                notes.append(line)

        body = re.sub(r'(?m)^\s*;.*?$', '', m.group('body')).strip()
        codes = []
        for line in body.splitlines():
            parts = line.split()
            if len(parts) != 2:
                continue
            try:
                codes.append((int(parts[0], 16), int(parts[1], 16)))
            except ValueError:
                pass

        enabled = bool(pending_enabled)
        pending_enabled = None
        if not codes:
            continue

        parts = _split_path(m.group('name').strip())
        if not parts:
            continue
        parent = _ensure_group(root, parts[:-1])
        parent.append(make_cheat(parts[-1], codes, enabled=enabled,
                                 desc=" ".join(notes), author=author))
    return root, meta


def read_cheat_file(path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        return parse_cheat_text(f.read())


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------
def _walk(nodes, prefix=""):
    for n in nodes:
        p = f"{prefix}\\{n['name']}" if prefix else n['name']
        yield p, n
        if is_group(n):
            yield from _walk(n['children'], p)


def render_cheat_text(title, serial, titleid, kind, tree):
    """
    Render a tree to the on-disk format. Inverse of parse_cheat_text.

    Groups and cheats are emitted interleaved, in depth-first tree order, so
    the reader can rebuild the tree by simply replaying the file top to bottom.
    Emitting all the groups up front instead would reorder siblings on reload.
    """
    out = [f"//game={title}",
           f"//serial={serial}",
           f"//titleid={titleid}",
           f"//kind={kind}",
           ""]

    def emit(nodes, parents=()):
        for n in nodes:
            path = parents + (n['name'],)
            p = _join_path(path)
            if is_group(n):
                out.append(f"//group={p}")
                if not n.get('expanded', True):
                    out.append(f"//collapsed={p}")
                out.append("")
                emit(n['children'], path)
            else:
                body = "\n".join(f"  {c:08X} {v:08X}" for c, v in n['codes'])
                head = f"//enabled={1 if n.get('enabled') else 0}\n"
                if n.get('author'):
                    head += f"; Author: {n['author']}\n"
                if n.get('desc'):
                    head += "".join(f"; {ln}\n"
                                    for ln in n['desc'].splitlines())
                out.append(f"{head}[{p}] {{\n{body}\n}}")
                out.append("")

    emit(tree)
    return "\n".join(out).rstrip() + "\n"


def write_cheat_file(path, title, serial, titleid, kind, tree):
    """Write atomically: temp file then rename, so a crash cannot truncate."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    text = render_cheat_text(title, serial, titleid, kind, tree)
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(text)
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------
def discover(base_dir):
    """
    Scan both folders independently.

    Returns {stem: {'cheats': path, 'patches': path}} -- a game may appear
    under one kind, both, or neither.
    """
    found = {}
    for kind, folder in (("cheats", CHEATS_DIR), ("patches", PATCHES_DIR)):
        d = os.path.join(base_dir, folder)
        if not os.path.isdir(d):
            continue
        for fn in os.listdir(d):
            if not fn.lower().endswith('.txt'):
                continue
            # Keep the real filename stem. Upper-casing it here made save
            # write YAKUZA.txt next to the existing Yakuza.txt on the next
            # cycle -- 86 duplicate files on a case-sensitive filesystem.
            stem = fn[:-4]
            found.setdefault(stem, {})[kind] = os.path.join(d, fn)
    return found
