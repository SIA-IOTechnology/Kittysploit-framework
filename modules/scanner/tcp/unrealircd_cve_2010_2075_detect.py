#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects UnrealIRCd banner on IRC port."""

import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "UnrealIRCd CVE-2010-2075 Detect",
        "description": "Detects UnrealIRCd banner on IRC port.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2010-2075"],
        "tags": ["scanner", "tcp", "unrealircd", "cve-2010-2075"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2010-2075"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/linux/misc/unrealircd_cve_2010_2075_rce"],
            },
        },
    }

    port = OptPort(6667, "Target port", required=False)

    def run(self):
        host = str(self.target or "")
        port = int(self.port or 6667)
        try:
            with socket.create_connection((host, port), timeout=8) as sock:
                sock.settimeout(5)
                banner = sock.recv(512).decode(errors="replace").lower()
        except OSError:
            return False
        if "unreal" in banner:
            self.set_info(severity="critical", cve="CVE-2010-2075", reason=f"UnrealIRCd banner: {banner[:80]}", confidence="high")
            return True
        return False
