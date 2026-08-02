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
import xemu_privs


if __name__ == "__main__":
    # Require the ability to read foreign process memory -- which is not the
    # same thing as being root. See xemu_privs for why, and for what happens
    # to file ownership when this is run under sudo anyway.
    xemu_privs.require_memory_access("Xemu Cheat Engine")

    trainer_engine = XemuTrainerEngine()
    app = TrainerWindow(trainer_engine)
    app.mainloop()
