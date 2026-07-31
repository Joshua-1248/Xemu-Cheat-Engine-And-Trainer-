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


if __name__ == "__main__":
    if platform.system() == "Linux" and os.geteuid() != 0:
        print("[-] Error: Run with sudo."); sys.exit(1)
    if platform.system() == "Windows" and not ctypes.windll.shell32.IsUserAnAdmin():
        print("[-] Error: Run as Administrator."); sys.exit(1)

    app = CheatManagerApp()
    app.mainloop()
