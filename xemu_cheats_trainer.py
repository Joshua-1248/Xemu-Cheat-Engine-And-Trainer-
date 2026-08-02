#!/usr/bin/env python3
# ===========================================================================
# Xemu Cheat Manager – Standalone game/cheat manager (INI database, PS2rd engine)
# ===========================================================================
# - Auto‑connects to Xemu (Linux/Windows).
# - Manages a game list with cheat files or built‑in cheat blocks.
# - Add / edit / remove cheats directly in the GUI.
# - Continuously applies enabled cheats.

# ---------------------------------------------------------------------------
# Implementation lives in ./xemu_trainer_lib/ — see xemu_trainer_lib/__init__.py
# for the module map. This file is only the launcher.
# ---------------------------------------------------------------------------

import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from xemu_trainer_lib.prelude import *  # noqa: F401,F403  (ctypes, os, platform, sys)
from xemu_trainer_lib.app import CheatManagerApp  # noqa: F401
import xemu_privs


if __name__ == "__main__":
    xemu_privs.require_memory_access("Xemu Cheat Manager")

    app = CheatManagerApp()
    app.mainloop()
