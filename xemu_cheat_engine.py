#!/usr/bin/env python3
# ===========================================================================
# Xemu Cheat Engine – Fully functional, settings persistent, auto‑highlight
# ===========================================================================
# This script attaches to a running Xemu emulator, scans the emulated Xbox's
# RAM, and allows you to find, edit, freeze, and create pointer‑based cheats.
# It includes a memory scanner, a hex memory viewer, and a pointer finder.
#

# ---------------------------------------------------------------------------
# Implementation lives in ./xemu_engine_lib/ — see xemu_engine_lib/__init__.py
# for the module map. This file is only the launcher.
# ---------------------------------------------------------------------------

import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from xemu_engine_lib.prelude import *  # noqa: F401,F403  (ctypes, os, platform, sys)
from xemu_engine_lib.engine_core import XemuTrainerEngine  # noqa: F401
from xemu_engine_lib.trainer_window import TrainerWindow  # noqa: F401


if __name__ == "__main__":
    # Require root on Linux, Administrator on Windows
    if platform.system() == "Linux" and os.geteuid() != 0:
        print("[-] Error: Run with sudo."); sys.exit(1)
    if platform.system() == "Windows" and not ctypes.windll.shell32.IsUserAnAdmin():
        print("[-] Error: Run as Administrator."); sys.exit(1)

    trainer_engine = XemuTrainerEngine()
    app = TrainerWindow(trainer_engine)
    app.mainloop()
