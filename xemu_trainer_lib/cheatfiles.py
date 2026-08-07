"""Cheat/patch file discovery, reading and writing.

Layout, beside the INI:

    xemu_cheat_manager.ini
    cheats/SERIAL_TITLEID.txt
    patches/SERIAL_TITLEID.txt

The two folders are scanned independently. A game may have a cheats file, a
patches file, both, or neither -- there is no single path pointing at one of
them.

The body follows PCSX2's pnach 2.0 shape: a bracketed name opens a block, and
everything under it belongs to that block until the next bracketed name or the
end of the file. There is no closing delimiter.

    gametitle=Doom 3 - Collector's Edition

    [Widescreen 16:9]
    author=Josh_7774
    enabled=0
    A04FB0FC 40D80000

A block with code lines is a cheat; a block with none is a group declaration,
which is what preserves empty groups and sibling order. Block keys are
`author=`, `desc=` (repeatable), `enabled=`, and `collapsed=` on a group. Code
lines are the raw ps2rd pair -- two hex words, no 0x -- that pnach was built on.

The header is one line. `kind` is not written, because the folder already says
which it is and nothing reads it back; `serial` and `titleid` are not written
when the SERIAL_TITLEID filename already carries them, which is every file that
has them. `//` means nothing to the parser and is free to use as a comment.

Two older shapes still load, and may be mixed with the current one in a single
file: the `//game=` / `//group=` / `//enabled=` directive header, and the
`; Author:` plus `[Name] { ... }` brace form before it. Only the current shape
is ever written, so a file converts itself the first time the trainer saves it.

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
# A block header: a line holding nothing but a bracketed name. The trailing
# `\{?` accepts the oldest brace form, so files written before this change
# still load.
#
# `(.*)` is greedy, so it backtracks to the LAST `]` on the line. That is what
# lets a name containing brackets through -- two games here have a group
# literally called `[ASM]`, and a non-greedy or `[^\]]*` pattern drops those
# blocks silently.
_HEAD = re.compile(r'^\[(.*)\][ \t]*\{?[ \t]*$')

# A code line: the raw ps2rd pair that pnach was built on -- two hex words,
# whitespace separated, no 0x prefix. Short forms are accepted because
# hand-written files use them; render always pads to eight.
_CODE = re.compile(r'^([0-9A-Fa-f]{1,8})[ \t]+([0-9A-Fa-f]{1,8})[ \t]*$')

# A key. Cannot collide with a code line, which has no `=`.
_KV = re.compile(r'^([A-Za-z][A-Za-z0-9_ -]*?)[ \t]*=(.*)$')

# SERIAL_TITLEID, the filename stem. Serial and title id are not written into
# the file when the name already carries them -- which is every file that has
# them at all.
_STEM = re.compile(r'^([A-Za-z]{2}-[0-9]{3})_([0-9A-Fa-f]{8})$')

# `//` directives from older files. Read, never written. Anything else on a
# `//` line is a comment and is ignored without closing the open block.
_LEGACY_DIRECTIVES = ('game', 'serial', 'titleid', 'kind', 'group',
                      'collapsed', 'enabled')

FILE_KEYS = ('gametitle', 'game', 'serial', 'titleid', 'kind')


def split_stem(stem):
    """`AV-032_41560020` -> ('AV-032', '41560020'). ('', '') if it is a slug."""
    m = _STEM.match(stem or '')
    return (m.group(1), m.group(2).upper()) if m else ('', '')


def _split_path(name, slash=False):
    r"""
    Split a group path on unescaped backslash.

    Backslash alone is the separator here, NOT backslash-or-slash. One of the
    groups in this database is literally named "Driving/On-Rails" -- treating
    `/` as a separator silently turns that single group into two nested ones.
    A literal backslash in a name is written `\\`.

    `slash=True` additionally treats `/` as a separator. That is what the
    clipboard importer passes, because forum-posted blocks are written either
    way and a pasted cheat is not expected to round-trip. Files never pass it.
    """
    parts, cur, i = [], [], 0
    while i < len(name):
        ch = name[i]
        if slash and ch == '/':
            parts.append(''.join(cur))
            cur = []
            i += 1
            continue
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


def logical_lines(content):
    """
    Yield (source_line_number, unit) for each syntactic unit.

    The line number is the real one from the file, so a warning points at
    something the user can actually find in a text editor.

    Almost every line is already one unit. The exception is the oldest form,
    written all on one line -- `[Name] { AAAAAAAA BBBBBBBB }` -- which the
    original regex parser accepted and which would otherwise stop loading.

    The bracketed name is taken off the front first, up to the LAST `]` on the
    line, so a brace inside a cheat's own name is never mistaken for a
    delimiter. Only what remains after the name is split on braces.
    """
    for lineno, raw in enumerate(content.splitlines(), 1):
        s = raw.strip()
        if not s:
            continue
        if s.startswith('//') or s.startswith(';'):
            yield lineno, s
            continue
        if s.startswith('['):
            end = s.rfind(']')
            if end != -1:
                head, s = s[:end + 1], s[end + 1:].strip()
                # An opening brace still belongs to the header line, so that
                # `[Name] {` stays one unit and _HEAD matches it.
                if s.startswith('{'):
                    head, s = head + ' {', s[1:].strip()
                yield lineno, head
                if not s:
                    continue
        for piece in re.split(r'([{}])', s):
            piece = piece.strip()
            if piece:
                yield lineno, piece


def _apply_comment(block, line):
    """Read one `; ...` metadata line into a block-in-progress."""
    line = line.lstrip(';').strip()
    if not line:
        return
    low = line.lower()
    if low.startswith('author:'):
        block['author'] = line.split(':', 1)[1].strip()
    elif low.startswith(('desc:', 'description:')):
        block['notes'].append(line.split(':', 1)[1].strip())
    else:
        block['notes'].append(line)


def _truthy(val):
    return val.strip().lower() not in ('', '0', 'no', 'off', 'false')


def _apply_key(block, key, val):
    """Read one `key=value` line into a block-in-progress. True if known."""
    key, val = key.strip().lower(), val.strip()
    if key == 'author':
        block['author'] = val
    elif key in ('desc', 'description', 'note', 'notes'):
        block['notes'].append(val)
    elif key == 'enabled':
        block['enabled'] = _truthy(val)
    elif key == 'collapsed':
        block['collapsed'] = _truthy(val)
    else:
        return False
    return True


def parse_cheat_text(content, sep_slash=False):
    r"""
    Parse a cheat file into (tree, meta).

    Format:

        gametitle=Doom 3 - Collector's Edition

        [Widescreen 16:9]
        author=Josh_7774
        enabled=0
        A04FB0FC 40D80000

    A `[Name]` line opens a block. Everything under it belongs to that block
    until the next `[Name]` or end of file -- the rule PCSX2's pnach 2.0 uses.
    There is no closing delimiter, because metadata sits *below* the name: the
    parser never has to look ahead to decide whether a line belongs to the
    block above or the one below.

    A block with code lines is a cheat. A block with none is a group
    declaration, which is how empty groups and sibling order survive a save --
    `[Weapons]` before `[Weapons\Ammo\Rocket]` fixes where Weapons sits.
    `collapsed=1` on a group declaration loads it collapsed.

    `key=value` before the first `[Name]` sets file metadata: `gametitle=`,
    and `serial=`/`titleid=` only when the filename cannot supply them.

    `//` is a comment. It carries no meaning and does not interrupt a block.

    Two older shapes still load, and may be mixed with this one in a file:

      * `//game=` / `//group=` / `//collapsed=` / `//enabled=` directives;
      * `; Author:` lines above a `[Name] { ... }` block, braces and all.

    Anything unrecognised is reported in meta['warnings'] with a line number
    rather than being swallowed.
    """
    meta = {'game': '', 'serial': '', 'titleid': '', 'kind': '',
            'warnings': []}

    # Legacy //collapsed= is collected up front because it may follow the
    # //group= line it refers to, and those groups are created on sight.
    collapsed = {m.group(1).strip().lower() for m in
                 re.finditer(r'(?m)^\s*//collapsed=(.*)$', content)}

    root = []
    cur = None              # block under construction
    seen_block = False      # has any [Name] appeared yet?
    pending_head = []       # legacy `;` lines seen before a `[Name]`
    pending_enabled = None  # legacy `//enabled=` seen before a `[Name]`

    def new_block(parts):
        return {'parts': parts, 'codes': [], 'notes': [], 'author': '',
                'enabled': bool(pending_enabled), 'collapsed': False}

    def flush():
        """Commit the block under construction: a cheat, or a group."""
        nonlocal cur
        if cur is None:
            return
        blk, cur = cur, None
        if not blk['parts']:
            return
        if blk['codes']:
            parent = _ensure_group(root, blk['parts'][:-1])
            parent.append(make_cheat(blk['parts'][-1], blk['codes'],
                                     enabled=blk['enabled'],
                                     desc=" ".join(blk['notes']),
                                     author=blk['author']))
        else:
            _ensure_group(root, blk['parts'], expanded=not blk['collapsed'])

    def set_file_key(key, val):
        if key in ('gametitle', 'game'):
            meta['game'] = val
        elif key in ('serial', 'titleid', 'kind'):
            meta[key] = val

    for lineno, line in logical_lines(content):
        if line in ('{', '}'):
            if line == '}':
                flush()
            continue

        if line.startswith('//'):
            key, sep, val = line[2:].partition('=')
            key, val = key.strip().lower(), val.strip()
            if not (sep and key in _LEGACY_DIRECTIVES):
                continue            # an ordinary comment: no effect at all
            if key in FILE_KEYS:
                set_file_key(key, val)
                continue
            # A legacy structural directive ends the block it follows.
            flush()
            if key == 'group':
                parts = _split_path(val, sep_slash)
                if parts:
                    _ensure_group(root, parts,
                                  expanded=val.lower() not in collapsed)
            elif key == 'enabled':
                pending_enabled = (val == '1')
            continue

        head = _HEAD.match(line)
        if head:
            flush()
            seen_block = True
            parts = _split_path(head.group(1).strip(), sep_slash)
            cur = new_block(parts)
            for c in pending_head:
                _apply_comment(cur, c)
            pending_head, pending_enabled = [], None
            if not parts:
                meta['warnings'].append(f"line {lineno}: block has no name")
                cur = None
            continue

        if line.startswith(';'):
            # Above a block this is legacy metadata; inside one, treat it the
            # same way so hand-edited files behave predictably either way.
            if cur is None:
                pending_head.append(line)
            else:
                _apply_comment(cur, line)
            continue

        code = _CODE.match(line)
        if code:
            if cur is None:
                meta['warnings'].append(
                    f"line {lineno}: code line before any [Name]")
            else:
                cur['codes'].append((int(code.group(1), 16),
                                     int(code.group(2), 16)))
            continue

        kv = _KV.match(line)
        if kv:
            key, val = kv.group(1).strip(), kv.group(2)
            if cur is None and not seen_block:
                if key.lower() in FILE_KEYS:
                    set_file_key(key.lower(), val.strip())
                else:
                    meta['warnings'].append(
                        f"line {lineno}: unknown file key {key!r}")
            elif cur is None:
                meta['warnings'].append(
                    f"line {lineno}: {key}= belongs to no [Name]")
            elif not _apply_key(cur, key, val):
                meta['warnings'].append(
                    f"line {lineno}: unknown key {key!r}")
            continue

        meta['warnings'].append(f"line {lineno}: not understood: {line!r}")

    flush()
    return root, meta


def parse_pasted_text(content):
    """
    Same grammar, for text off the clipboard or a hand-written .cht.

    Returns the tree only. `/` is accepted as a group separator here because
    posted blocks use it and pasted text is not expected to round-trip; files
    keep backslash-only so a group named "Driving/On-Rails" survives a save.
    """
    tree, _ = parse_cheat_text(content, sep_slash=True)
    return tree


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


def render_cheat_text(title, serial, titleid, kind=None, tree=(), stem=None):
    r"""
    Render a tree to the on-disk format. Inverse of parse_cheat_text.

    The header is one line. `kind` is never written: the folder the file sits
    in already says whether it holds cheats or patches, and nothing reads it
    back. `serial`/`titleid` are written only when `stem` cannot supply them,
    which in practice means only the handful of games with no known title id
    -- and those have no serial or title id to write either, so in practice
    the header is `gametitle=` and nothing else.

    Groups are emitted as code-less `[Path]` blocks, interleaved with cheats in
    depth-first tree order, so the reader rebuilds the tree by replaying the
    file top to bottom. Emitting all the groups up front instead would reorder
    siblings on reload.
    """
    out = [f"gametitle={title}"]
    have_serial, have_titleid = split_stem(stem or '')
    if serial and serial.upper() != have_serial.upper():
        out.append(f"serial={serial}")
    if titleid and titleid.upper() != have_titleid.upper():
        out.append(f"titleid={titleid}")
    out.append("")

    def emit(nodes, parents=()):
        for n in nodes:
            path = parents + (n['name'],)
            p = _join_path(path)
            if is_group(n):
                # Declared even when it has children: the declaration is what
                # fixes where the group sits among its siblings. Without it a
                # group would spring into being at its first cheat instead.
                lines = [f"[{p}]"]
                if not n.get('expanded', True):
                    lines.append("collapsed=1")
                out.append("\n".join(lines))
                out.append("")
                emit(n['children'], path)
            else:
                lines = [f"[{p}]"]
                if n.get('author'):
                    lines.append(f"author={n['author']}")
                for ln in (n.get('desc') or '').splitlines():
                    if ln.strip():
                        lines.append(f"desc={ln.strip()}")
                # Always written, never inferred. make_cheat defaults to off,
                # so an omitted key and enabled=0 mean the same thing -- but
                # being explicit is what makes a hand-edited file obvious.
                lines.append(f"enabled={1 if n.get('enabled') else 0}")
                lines.extend(f"{c:08X} {v:08X}" for c, v in n['codes'])
                out.append("\n".join(lines))
                out.append("")

    emit(tree)
    return "\n".join(out).rstrip() + "\n"


def write_cheat_file(path, title, serial, titleid, kind, tree):
    """Write atomically: temp file then rename, so a crash cannot truncate."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    stem = os.path.splitext(os.path.basename(path))[0]
    text = render_cheat_text(title, serial, titleid, kind, tree, stem)
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(text)
    xemu_privs.reclaim(tmp)
    os.replace(tmp, path)
    # makedirs may have created the parent chain as root; hand that back too.
    xemu_privs.reclaim_tree(path)


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
