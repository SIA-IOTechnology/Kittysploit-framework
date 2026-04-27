#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.utils.venv_helper import ensure_venv
ensure_venv(__file__)


def _is_admin() -> bool:
    if os.name == "nt":
        try:
            import ctypes  # type: ignore
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


def _relaunch_as_admin() -> None:
    marker = "KITTYPROTOCOL_ELEVATION_ATTEMPTED"
    if os.environ.get(marker) == "1":
        return

    if os.name == "nt":
        try:
            import ctypes  # type: ignore

            params = " ".join(f'"{arg}"' for arg in sys.argv)
            rc = ctypes.windll.shell32.ShellExecuteW(  # type: ignore[attr-defined]
                None,
                "runas",
                sys.executable,
                params,
                None,
                1,
            )
            if int(rc) <= 32:
                print("[!] Unable to elevate to Administrator mode.")
                return
            raise SystemExit(0)
        except Exception:
            print("[!] Unable to elevate to Administrator mode.")
            return

    sudo_bin = shutil.which("sudo")
    if not sudo_bin:
        print("[!] KittyProtocol requires root privileges. Install sudo or run with: sudo python kittyprotocol.py")
        return

    env = dict(os.environ)
    env[marker] = "1"
    cmd = [sudo_bin, sys.executable] + sys.argv
    print("[*] KittyProtocol must be started with root privileges. Sudo password required to continue.")
    rc = subprocess.call(cmd, env=env)
    raise SystemExit(rc)


if __name__ == "__main__":
    if not _is_admin():
        _relaunch_as_admin()
    from interfaces.kittyprotocol import main
    main()
