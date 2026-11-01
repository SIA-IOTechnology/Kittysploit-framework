#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect FortiClient EMS registration SQLi (CVE-2023-48788, Horizon3)."""

from kittysploit import *
from lib.protocols.tcp.forticlient_ems_client import Forticlient_ems_client
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client, Forticlient_ems_client):
    __info__ = {
        "name": "FortiClient EMS CVE-2023-48788 Registration SQLi Detect",
        "description": (
            "Horizon3 probe: TLS registration message with SQLi; vulnerable hosts "
            "respond with KA_INTERVAL."
        ),
        "author": ["Horizon3 Attack Team", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2023-48788"],
        "references": [
            "https://github.com/horizon3ai/CVE-2023-48788",
            "https://www.horizon3.ai/attack-research/cve-2023-48788-fortinet-forticlientems-sql-injection-deep-dive",
        ],
        "tags": ["scanner", "tcp", "fortinet", "forticlient", "ems", "sqli"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals", "exploit_paths"],
            "chain": {
                "suggested_followups": [
                    "scanner/http/forticlient_ems_cve_2026_21643",
                ],
            },
        },
    }

    DEFAULT_PORT = 8013

    port = OptPort(DEFAULT_PORT, "FortiClient EMS TLS port", required=True)

    def run(self):
        host = self._host()
        if not host:
            return False
        port = int(self.port or self.DEFAULT_PORT)
        try:
            reply = self.send_forticlient_register(host, port)
        except OSError:
            return False

        if reply and b"KA_INTERVAL" in reply:
            self.set_info(
                severity="critical",
                cve="CVE-2023-48788",
                reason="FortiClient EMS registration SQLi probe returned KA_INTERVAL",
                path=f"{host}:{port}",
            )
            return True
        return False
