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
        severity = "low" if "none" in [str(m).lower() for m in methods] else "info"
        self.set_info(
            severity=severity,
            reason="SSH auth methods enumerated",
            methods=list(methods),
            banner=str(info.get("banner") or "")[:120],
            username=str(self.username or "root"),
        )
        return True
