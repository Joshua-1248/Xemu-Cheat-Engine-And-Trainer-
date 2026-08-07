# Cheat / patch file format

Files live beside the INI:

    xemu_cheat_manager.ini
    cheats/SERIAL_TITLEID.txt
    patches/SERIAL_TITLEID.txt

## Shape

    gametitle=Doom 3 - Collector's Edition

    [60 FPS]
    author=Josh_7774
    desc=Patches game to run at 60 FPS. Experimental.
    enabled=0
    8002F001 000000F0
    8002F036 00000010
    A002F083 000000A0

A `[Name]` line opens a block. Everything under it belongs to that block until
the next `[Name]` or the end of the file. There is no closing delimiter — this
is the rule PCSX2's pnach 2.0 uses.

Metadata sits **below** the name, not above it. That is what removes the need
for a delimiter: the parser never has to decide whether a line belongs to the
block above or the one below.

## Lines

| Line | Meaning |
|---|---|
| `gametitle=` | the game's display name — the one thing the filename cannot supply |
| `serial=` `titleid=` | only for games with no `SERIAL_TITLEID` filename; normally absent |
| `[Name]` **with** code lines | a cheat. `\` nests: `[Weapons\Ammo\Infinite Rockets]` |
| `[Name]` **without** code lines | a group declaration — this is what keeps empty groups and sibling order |
| `author=` | block author |
| `desc=` | block description; repeat the key for more lines |
| `enabled=` | `1`/`0` (also `yes/no`, `on/off`, `true/false`) |
| `collapsed=1` | on a group declaration: loads collapsed |
| `AAAAAAAA VVVVVVVV` | a code line — the raw ps2rd pair pnach was built on |
| `// anything` | comment. Means nothing to the parser, anywhere, including mid-block |
| `; anything` | comment |
| blank | ignored anywhere |

Keys before the first `[Name]` are file keys; keys after it belong to the open
block. That is the whole disambiguation rule.

Group paths split on backslash only. `/` is left alone, because one group in
this database is named `Driving/On-Rails` and splitting on `/` would quietly
turn it into two.

## What is deliberately not in the file

`kind=` is gone: the folder the file sits in already says whether it holds
cheats or patches, and nothing ever read the key back.

`serial=` and `titleid=` are gone from all 730-odd files named
`SERIAL_TITLEID.txt`, because the name already carries them. Duplicating them
inside gives two sources that can disagree after a rename. They are still
written for slug-named files, and still read if present, so a hand-written
file can override.

That leaves `gametitle=` as the only header line, and leaves `//` with no
meaning at all — free to use as a comment.

## Errors are reported

A line the parser cannot place is collected into `meta['warnings']` with its
source line number and printed to stderr at load, instead of being dropped:

    AV-032_41560020.txt: line 11: unknown key 'autor'
    AV-032_41560020.txt: line 12: not understood: 'ZZZZZZZZ 00000001'

## Older formats still load

Both earlier shapes parse, and may be mixed with the current one in one file:

    //game=Doom 3 - Collector's Edition      <- directive header
    //group=Weapons
    //enabled=0
    ; Author: Josh_7774
    [Widescreen 16:9] {                      <- brace form
      A04FB0FC 40D80000
    }

Only the current shape is ever written, so a file converts itself the first
time the trainer saves it. `convert_cheat_files.py` does the whole database in
one pass; it has already been run on the files in this tree.

## Names containing brackets

Six blocks in this database sit under a group literally called `[ASM]`, giving
names like `[[ASM]\Infinite Ammo - No Reload [ASM]]`. The header pattern takes
the name up to the **last** `]` on the line, so these parse whole. The original
`[^\]]*` pattern could not match them and dropped all six without a word; they
are present again as of this change.
