#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect FortiSIEM Phoenix Monitor TLS port (CVE-2025-64155)."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "FortiSIEM Phoenix Monitor Port Probe (CVE-2025-64155)",
        "description": "Checks whether TCP 7900 (Phoenix Monitor TLS) is reachable on the target.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": ["CVE-2025-64155"],
        "tags": ["scanner", "tcp", "fortinet", "fortisiem"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals", "endpoints"],
            "chain": {
                "suggested_followups": [
                    "exploits/multi/tcp/fortisiem_cve_2025_64155_rce",
                    "scanner/tcp/fortisiem_cve_2026_106173_detect",
                ],
            },
        },
    }

    DEFAULT_MONITOR_PORT = 7900

    port = OptPort(DEFAULT_MONITOR_PORT, "Phoenix Monitor port", required=True)

    def run(self):
        host = self._host()
        if not host:
            return False
        port = int(self.port or self.DEFAULT_MONITOR_PORT)
        if self.is_tcp_open(host, port):
            self.set_info(
                severity="high",
                reason=f"FortiSIEM Phoenix Monitor TCP {port} open on {host}",
                path=f"{host}:{port}",
            )
            return True
        return False
