#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects open ActiveMQ OpenWire port (ClassPathXmlApplicationContext chain)."""

import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "ActiveMQ CVE-2023-46604 Detect",
        "description": "Detects open ActiveMQ OpenWire port (ClassPathXmlApplicationContext chain).",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2023-46604"],
        "tags": ["scanner", "tcp", "activemq", "cve-2023-46604"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-46604"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/tcp/activemq_cve_2023_46604_rce"],
            },
        },
    }

    port = OptPort(61616, "Target port", required=False)

    def run(self):
        host = str(self.target or "")
        port = int(self.port or 61616)
        try:
            with socket.create_connection((host, port), timeout=8) as sock:
                pass
        except OSError:
            return False
        self.set_info(severity="critical", cve="CVE-2023-46604", reason=f"OpenWire TCP/{port} open", confidence="low")
        return True
