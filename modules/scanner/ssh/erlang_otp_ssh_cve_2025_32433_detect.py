#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Erlang/OTP SSH (CVE-2025-32433) — not generic OpenSSH."""

from __future__ import annotations

import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client

from lib.scanner.ssh.erlang_ssh import is_erlang_otp_ssh_banner

CVE_ID = "CVE-2025-32433"


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "Erlang OTP SSH CVE-2025-32433 Detect",
        "description": (
            "Flags CVE-2025-32433 only when the SSH banner identifies "
            "Erlang/OTP SSH (not OpenSSH, Dropbear, etc.)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": [CVE_ID],
        "tags": ["scanner", "tcp", "ssh", "erlang", "cve-2025-32433"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-32433"],
        "modules": ["exploits/linux/ssh/erlang_otp_ssh_cve_2025_32433_rce"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": [
                    "exploits/linux/ssh/erlang_otp_ssh_cve_2025_32433_rce"
                ],
            },
        },
    }

    port = OptPort(22, "SSH port", required=False)

    def run(self):
        host = self._host()
        port = int(self._port() or 22)
        if not host:
            return False
        try:
            with socket.create_connection((host, port), timeout=8) as sock:
                sock.settimeout(5)
                banner = sock.recv(256).decode(errors="replace")
        except OSError:
            return False
        if not is_erlang_otp_ssh_banner(banner):
            return False
        self.set_info(
            severity="critical",
            cve=CVE_ID,
            reason=f"Erlang OTP SSH banner: {banner.strip()[:160]}",
            confidence="high",
        )
        return True
