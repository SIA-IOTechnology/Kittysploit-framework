#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Redis-compatible PING on TCP (Valkey module RCE chain)."""

import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "Valkey/Redis CVE-2026-25243 Detect",
        "description": "Detects Redis-compatible PING on TCP (Valkey module RCE chain).",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-25243"],
        "tags": ["scanner", "tcp", "valkey", "cve-2026-25243"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-25243"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/linux/redis/valkey_cve_2026_25243_rce"],
            },
        },
    }

    port = OptPort(6379, "Target port", required=False)

    def run(self):
        host = str(self.target or "")
        port = int(self.port or 6379)
        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                sock.sendall(b"PING\r\n")
                sock.settimeout(3)
                data = sock.recv(128)
        except OSError:
            return False
        if data.startswith(b"+PONG") or b"redis" in data.lower():
            self.set_info(severity="critical", cve="CVE-2026-25243", reason="Redis/Valkey PONG", confidence="medium")
            return True
        return False
