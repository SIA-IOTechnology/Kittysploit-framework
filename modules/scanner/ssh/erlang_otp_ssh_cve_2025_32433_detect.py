#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects SSH banner (Erlang OTP SSH pre-auth RCE chain)."""

import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "Erlang OTP SSH CVE-2025-32433 Detect",
        "description": "Detects SSH banner (Erlang OTP SSH pre-auth RCE chain).",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2025-32433"],
        "tags": ["scanner", "tcp", "erlang", "cve-2025-32433"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-32433"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/linux/ssh/erlang_otp_ssh_cve_2025_32433_rce"],
            },
        },
    }

    port = OptPort(2222, "Target port", required=False)

    def run(self):
        host = str(self.target or "")
        port = int(self.port or 2222)
        try:
            with socket.create_connection((host, port), timeout=8) as sock:
                sock.settimeout(5)
                banner = sock.recv(256).decode(errors="replace")
        except OSError:
            return False
        if "SSH-" not in banner:
            return False
        conf = "medium" if "erlang" in banner.lower() else "low"
        self.set_info(severity="critical", cve="CVE-2025-32433", reason=f"SSH banner: {banner.strip()[:120]}", confidence=conf)
        return True
