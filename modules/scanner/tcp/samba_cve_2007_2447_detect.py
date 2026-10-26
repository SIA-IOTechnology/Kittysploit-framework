#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects open SMB session port (username map script RCE chain)."""

import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "Samba CVE-2007-2447 Detect",
        "description": "Detects open SMB session port (username map script RCE chain).",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2007-2447"],
        "tags": ["scanner", "tcp", "samba", "cve-2007-2447"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2007-2447"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/linux/smb/samba_cve_2007_2447_rce"],
            },
        },
    }

    port = OptPort(445, "Target port", required=False)

    def run(self):
        host = str(self.target or "")
        port = int(self.port or 445)
        try:
            with socket.create_connection((host, port), timeout=8) as sock:
                pass
        except OSError:
            return False
        self.set_info(severity="critical", cve="CVE-2007-2447", reason=f"TCP/{port} open (Samba usermap chain)", confidence="low")
        return True
