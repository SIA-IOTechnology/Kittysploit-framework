#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect SSH accounts accepting an empty password."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.ssh.detectors import probe_ssh_empty_password


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "SSH Empty Password",
        "description": (
            "Tests common usernames for empty-password SSH login. "
            "Requires Paramiko. Authorized targets only."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["ssh", "auth", "credentials", "misconfig", "scanner", "vuln"],
        "agent": {
            "risk": "intrusive",
            "effects": ["credential_spray", "network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["credentials", "risk_signals"],
            "chain": {
                "produces_capabilities": [
                    {"capability": "ssh_access", "from_detail": "username"},
                    "authenticated_session",
                ],
                "consumes_capabilities": ["service_identified", "ssh_auth_surface"],
                "option_bindings": {},
                "suggested_followups": [
                    "auxiliary/scanner/ssh/ssh_login_bruteforce",
                    "post/shell/linux/gather/enum_system",
                ],
            },
        },
    }

    port = OptPort(22, "SSH port", True)
    usernames = OptString(
        "root,admin,ubuntu,user",
        "Comma-separated usernames to test with an empty password",
        False,
    )

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        users = [
            u.strip()
            for u in str(self.usernames or "root,admin").split(",")
            if u.strip()
        ]
        info = probe_ssh_empty_password(
            host=host,
            port=port,
            timeout=max(self._timeout(), 8.0),
            usernames=users,
        )
        if info.get("error") == "paramiko_required":
            print_info("Paramiko required for SSH empty-password probe")
            return False
        if not info.get("success"):
            return False
        user = str(info.get("username") or "")
        banner = str(info.get("banner") or "").strip()
        reason = f"SSH empty password accepted for {user}"
        if banner:
            reason = f"{reason} | banner={banner}"
        self.report_finding(
            "SSH empty password accepted",
            severity="high",
            evidence={
                "host": host,
                "port": port,
                "username": user,
                "password": "(empty)",
                "banner": banner,
            },
            impact={
                "summary": "An attacker can authenticate without a password.",
                "business_risk": "Full remote shell access",
            },
            remediation={
                "summary": "Disable empty passwords and enforce strong credentials.",
                "actions": [
                    "Set PermitEmptyPasswords no",
                    "Prefer publickey authentication",
                    "Review and lock accounts with blank passwords",
                ],
            },
        )
        self.set_info(
            severity="high",
            reason=reason,
            username=user,
            password="",
            banner=banner,
        )
        return True
