#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Enable persistent root execution for subsequent Linux post modules."""

from __future__ import annotations

import shlex

from kittysploit import *
from lib.post.linux.system import System
from lib.post.linux.session import LinuxSessionMixin
from core.framework.shell.root_elevate import (
    METHOD_NATIVE,
    METHOD_SUDO_NOPASSWD,
    METHOD_SUDO_PASSWORD,
    ROOT_ELEVATE_FLAG,
    ROOT_ELEVATE_METHOD,
    ROOT_ELEVATE_PASSWORD,
    get_root_elevate_config,
    is_root_uid_output,
    parse_uid_output,
)


class Module(Post, System, LinuxSessionMixin):
    __info__ = {
        "name": "Elevate Session (Keep Root)",
        "description": (
            "Marks the active Linux/SSH session so subsequent post modules run as root, "
            "and auto-escalates SSH interactive PTY sessions (sudo -i) on sessions interact. "
            "Uses native root when already uid 0, otherwise sudo -n or sudo -S with a password. "
            "Solves SSH sessions where interactive sudo/su is lost after 'back'."
        ),
        "author": ["KittySploit Team"],
        "platform": [Platform.LINUX],
        "session_type": [SessionType.SHELL, SessionType.SSH, SessionType.METERPRETER],
        "tags": ["privilege-escalation", "sudo", "session", "linux"],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.0,
            "requires": {
                "capabilities_any": ["shell"],
                "capabilities_all": [],
            },
            "chain": {
                "consumes_capabilities": ["shell"],
                "produces_capabilities": ["root"],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    action = OptChoice("enable", "enable | disable | status", required=True, choices=["enable", "disable", "status"])
    password = OptString("","sudo password (empty = try NOPASSWD, then session SSH password)",required=False)

    def _opt_str(self, opt) -> str:
        if hasattr(opt, "value"):
            return str(opt.value or "")
        return str(opt or "")

    def _sid(self) -> str:
        return self._linux_sid()

    def _probe(self, command: str) -> str:
        return self.linux_execute(command, pty=False) or ""

    def _raw_uid(self, command: str) -> str:
        """Run a probe and extract numeric uid (handles id -u and full id output)."""
        return parse_uid_output(self._probe(command))

    def _session_login_password(self) -> str:
        sid = self._sid()
        if not sid or not self.framework:
            return ""
        session = self.framework.session_manager.get_session(sid)
        if not session or not isinstance(getattr(session, "data", None), dict):
            return ""
        pw = session.data.get("password")
        return str(pw) if pw is not None else ""

    def _try_sudo_nopasswd(self) -> bool:
        return is_root_uid_output(self._probe("sudo -n -- id -u 2>/dev/null"))

    def _try_sudo_password(self, password: str) -> bool:
        if not password:
            return False
        qpw = shlex.quote(password)
        return is_root_uid_output(
            self._probe(f"printf '%s\\n' {qpw} | sudo -S -p '' -- id -u 2>/dev/null")
        )

    def _persist(self, *, enabled: bool, method: str = "", password: str = "") -> bool:
        sid = self._sid()
        if not sid:
            print_error("Session ID is required.")
            return False
        ok = self.framework.session_manager.update_session_data(
            sid,
            {
                ROOT_ELEVATE_FLAG: bool(enabled),
                ROOT_ELEVATE_METHOD: method if enabled else "",
                ROOT_ELEVATE_PASSWORD: password if enabled and method == METHOD_SUDO_PASSWORD else "",
            },
        )
        if not ok:
            print_error("Failed to update session data.")
        return ok

    def _print_status(self) -> bool:
        cfg = get_root_elevate_config(self.framework, self._sid())
        uid = self._raw_uid("id -u 2>/dev/null")
        who_out = self._probe("id -un 2>/dev/null")
        who_lines = [ln.strip() for ln in who_out.splitlines() if ln.strip()]
        who = who_lines[-1] if who_lines else "?"
        if who.isdigit() and uid == "0":
            who = "root"
        print_status(f"Current uid={uid or '?'} user={who or '?'}")
        if cfg:
            method = cfg.get("method") or "?"
            print_success(f"Root elevate is ON (method={method}).")
            if method != METHOD_NATIVE and uid != "0":
                print_warning(
                    "Elevate flag is set but id -u is not 0 — sudo may have failed; re-run action=enable."
                )
        else:
            print_info("Root elevate is OFF.")
            if uid != "0":
                print_info("Post modules will run as the session user until you enable elevation.")
        return True

    def check(self):
        return self.linux_require_linux()

    def run(self):
        if not self.check():
            return False

        action = self._opt_str(self.action).strip().lower() or "enable"

        if action == "status":
            return self._print_status()

        if action == "disable":
            if not self._persist(enabled=False):
                return False
            print_success("Root elevate disabled for this session.")
            uid = self._raw_uid("id -u 2>/dev/null")
            print_status(f"Commands now run as uid={uid or '?'}.")
            return True

        if action != "enable":
            print_error(f"Unknown action: {action}")
            return False

        if is_root_uid_output(self._probe("id -u 2>/dev/null")):
            if not self._persist(enabled=True, method=METHOD_NATIVE):
                return False
            print_success("Session is already root — elevate marked as native.")
            return True

        password = self._opt_str(self.password)
        if not password:
            password = self._session_login_password()

        if self._try_sudo_nopasswd():
            if not self._persist(enabled=True, method=METHOD_SUDO_NOPASSWD):
                return False
            print_success("sudo NOPASSWD works — subsequent post modules will run as root.")
        elif password and self._try_sudo_password(password):
            if not self._persist(enabled=True, method=METHOD_SUDO_PASSWORD, password=password):
                return False
            print_success("sudo with password works — subsequent post modules will run as root.")
            print_warning("Password is kept in session memory for command wrapping.")
        else:
            print_error(
                "Cannot elevate: not root, and sudo failed. "
                "Set PASSWORD to the sudo password, or open a root SSH session."
            )
            return False

        verify_out = self._probe("id -u 2>/dev/null")
        verify = parse_uid_output(verify_out)
        if verify == "0":
            print_success("Verified: id -u == 0 via elevated session.")
            return True

        print_warning(
            f"Elevate flag stored but verification returned uid={verify or '?'}. "
            "Try action=status or re-enable with PASSWORD."
        )
        return False
