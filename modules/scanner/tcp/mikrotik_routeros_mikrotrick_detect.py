#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect MikroTik RouterOS MikroTrick chain surface (CVE-2026-86060 / 67279 / 67277)."""

import socket

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "MikroTik RouterOS MikroTrick Chain Detect",
        "description": (
            "Detects exposure to the MikroTrick exploit chain in MikroTik RouterOS before "
            "6.49.21 / 7.23.4 / 7.24.2: SSH ROSSSH banner (CVE-2026-86060 / CVE-2026-67279) "
            "and reachable btest bandwidth-server on TCP/2000 (CVE-2026-67277). "
            "Does not attempt authentication bypass or kernel memory disclosure."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-86060", "CVE-2026-67279", "CVE-2026-67277"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-86060",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-67279",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-67277",
            "https://www.cisa.gov/news-events/alerts/2025/09/05/cisa-adds-three-known-exploited-vulnerabilities-catalog",
        ],
        "tags": [
            "scanner",
            "tcp",
            "mikrotik",
            "routeros",
            "ssh",
            "btest",
            "mikrotrick",
            "kev",
            "cve-2026-86060",
            "cve-2026-67279",
            "cve-2026-67277",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 1.0,
            "noise": 0.25,
            "value": 1.2,
            "requires": {
                "tech_hints_any": ["mikrotik", "routeros"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "auth_bypass_surface", "from_detail": "SSH policy mask"},
                    {"capability": "memory_disclosure_surface", "from_detail": "btest TCP/2000"},
                ],
                "suggested_followups": [
                    "scanner/tcp/mikrotik_ftp_detect",
                ],
            },
        },
    }

    ssh_port = OptPort(22, "RouterOS SSH port", True)
    btest_port = OptPort(2000, "RouterOS btest TCP port", True)

    def _read_banner(self, port: int) -> str:
        host = self._host()
        if not host or not self.is_tcp_open(host=host, port=port):
            return ""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout())
            sock.connect((host, port))
            data = sock.recv(256)
            sock.close()
        except Exception:
            return ""
        return (data or b"").decode("utf-8", errors="replace")

    def _btest_open(self) -> bool:
        host = self._host()
        port = int(self.btest_port or 2000)
        return bool(host and self.is_tcp_open(host=host, port=port))

    def run(self):
        ssh_banner = self._read_banner(int(self.ssh_port or 22))
        routeros_ssh = "ROSSSH" in ssh_banner or "MikroTik" in ssh_banner
        btest_exposed = self._btest_open()

        if not routeros_ssh and not btest_exposed:
            return False

        reasons = []
        if routeros_ssh:
            reasons.append("RouterOS SSH (ROSSSH) reachable")
        if btest_exposed:
            reasons.append("btest TCP/2000 exposed (CVE-2026-67277 surface)")

        severity = "critical" if (routeros_ssh and btest_exposed) else "high"
        self.set_info(
            severity=severity,
            reason="; ".join(reasons),
            ssh_banner=ssh_banner.strip() or "unknown",
            btest_port=int(self.btest_port or 2000),
        )
        return True
