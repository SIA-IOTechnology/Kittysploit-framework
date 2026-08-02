#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SSH authentication methods (NSE ssh-auth-methods)."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.ssh.detectors import probe_ssh_auth_methods


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "SSH Auth Methods",
        "description": (
            "Lists SSH user-authentication methods offered for a username "
            "(NSE ssh-auth-methods). Requires Paramiko."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "references": ["https://nmap.org/nsedoc/scripts/ssh-auth-methods.html"],
        "tags": ["ssh", "auth", "scanner", "discovery"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "produces_capabilities": [
                    "service_identified",
                    "ssh_auth_surface",
                    "remote_access",
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "scanner/ssh/ssh_empty_password_detect",
                    "auxiliary/scanner/ssh/ssh_login_bruteforce",
                ],
            },
        },
    }

    port = OptPort(22, "SSH port", True)
    username = OptString("root", "Username used for auth method discovery", False)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        info = probe_ssh_auth_methods(
            host=host,
            port=port,
            timeout=max(self._timeout(), 8.0),
            username=str(self.username or "root"),
        )
        if not info.get("detected"):
            return False
        methods = info.get("methods") or []
        if not methods and info.get("error") == "paramiko_required_for_auth_methods":
            print_info("Paramiko required to enumerate SSH auth methods")
            return False
        username = str(self.username or "root")
        method_list = [str(m) for m in methods]
        method_lc = [m.lower() for m in method_list]
        severity = "info"
        if "none" in method_lc:
            severity = "low"
        elif any(m in method_lc for m in ("password", "keyboard-interactive")):
            severity = "low"
        if method_list:
            reason = f"Auth methods for {username}: {', '.join(method_list)}"
        else:
            reason = f"No auth methods offered for {username}"
        banner = str(info.get("banner") or "").strip()
        if banner:
            reason = f"{reason} | banner={banner}"
        self.set_info(
            severity=severity,
            reason=reason,
            methods=method_list,
            banner=banner,
            username=username,
            password_auth_offered=any(
                m in method_lc for m in ("password", "keyboard-interactive")
            ),
        )
        return True
