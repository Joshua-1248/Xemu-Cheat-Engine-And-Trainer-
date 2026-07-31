# What changed in this round

## 1. The INI no longer holds games

`Config.load` now builds the game list by scanning `cheats/` and `patches/`.
A game exists because it has a file, not because it has an INI section.

`Config.save` writes **settings only** — geometry, freeze interval, sort mode,
and the game ordering. No `[game:...]` sections, no JSON mirror. Duplicating
every cheat in two places would just create a second copy that can drift.

Your INI drops from 92 KB to 16 KB, nearly all of which is the ordering list.

Backwards compatible: a legacy INI with `[game:...]` sections still loads those
sections for any game that has no file yet. On the next save they become files.

## 2. Every game has both files

1472 files — 736 games x 2. Empty ones are written too, and an emptied game's
file is **not** deleted, because the folders are the database now and deleting
would drop the game entirely.

Naming: `SERIAL_TITLEID.txt` for 693 games, a name slug for the other 43.

## 3. Title id coverage: 685 -> 693

A conservative second pass, no fuzzy scoring. Only two mechanisms:

- exact match after stripping every non-alphanumeric character
  (`SpyHunter 2` = `Spy Hunter 2`, `Night Caster` = `NightCaster`)
- a hand-checked alias table, one line per decision

Fuzzy matching was tried and rejected. difflib confidently returns
`Sonic Heroes` for `Bionicle Heroes`, `NBA Live 07` for `NBA Live 08`,
`Spider-Man 2` for `Spider-Man 3`, `MLB SlugFest 2006` for `2005`. A wrong
title id is worse than a blank one, so those stay blank.

Newly matched (14): Capcom Fighting Evolution, Fire Blade, Ford Bold Moves
Street Racing, Marvel vs. Capcom 2, Neighbors from Hell, NightCaster II,
Pro Cast Sports Fishing, both SpongeBob titles, Spy Hunter 2, Steel Battalion:
Line of Contact, Ty 3, UFC: Tapout 2, Yetisports Arctic Adventure.

Still blank (43) — they get slug filenames and work normally:

- **37 not in the database.** Mostly late or region-limited releases:
  Bionicle Heroes, Blinx 2, King Kong, Lost Planet, Mega Man X7/X8, Mercenaries,
  Spider-Man 3, Yakuza, Winx Club, Warhammer 40,000: Fire Warrior, and so on.
- **2 not original Xbox titles at all:** Master Chief Collection (Xbox One),
  Pokemon XD: Gale of Darkness (GameCube).
- **1 absent variant:** Hunter: The Reckoning - Wayward; the database has only
  the first Hunter: The Reckoning.
- **6 second claimants on a shared id**, which would collide: plain Doom 3
  (Collector's Edition owns AV-032), JSRF, Dead or Alive 2 Ultimate, and the
  three `Tom Clancy's Ghost Recon` duplicates.

## 4. Game ID box in the trainer

A read-only field above **Author:**, showing `MS-100  (4D530064)`.

It is an `Entry` with `state="readonly"` rather than a `Label`, so the id can
still be selected and copied — the point of showing an id — but not typed over.
It belongs to the selected game, not the selected cheat, so it is filled in by
`_display_cheats` and is **not** cleared when you click between cheats.

Games with no title id show `—  (no title id)` in grey.

Row order in that panel is now Game ID, Author, Description.

## 5. Two bugs fixed on the way

- **`discover()` upper-cased the filename stem.** On the next save that wrote
  `YAKUZA.txt` beside the existing `Yakuza.txt` — 86 duplicate files on a
  case-sensitive filesystem. It now keeps the real case.
- **An empty section could delete another's file.** File ownership is now
  decided in a pre-pass before anything is touched, and a game holding cheats
  always beats an empty one.

## Verified

| Check | Result |
|---|---|
| Games loaded from folders alone | 736 |
| Cheats / patches | 78 / 2 = 80, matches source |
| Enabled flags after load -> save -> load | 80 checked, **0 changed** |
| Files after save | 1472, byte-identical |
| Game list load -> save -> load | fixed point |
| INI after save | `['main']` only, 16 KB |
| `verify_cheatdb.py` | PASS, every code accounted for |
| All modules import | 14 + 12 |
