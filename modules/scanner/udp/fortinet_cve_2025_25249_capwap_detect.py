#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Fortinet FortiOS CAPWAP cw_acd surface (CVE-2025-25249)."""

import socket
import struct

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "Fortinet FortiOS CVE-2025-25249 CAPWAP Detect",
        "description": (
            "Detects CVE-2025-25249 exposure by probing UDP/5246 with a benign CAPWAP "
            "Discovery Request. A response from cw_acd indicates the fabric/CAPWAP "
            "control plane is reachable; combine with FortiOS version inventory to "
            "assess patch status (fixed in 7.6.4 / 7.4.9 / 7.2.12 / 7.0.18 / 6.4.17)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2025-25249"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2025-25249",
            "https://www.fortiguard.com/psirt/FG-IR-25-647",
        ],
        "tags": [
            "scanner",
            "udp",
            "fortinet",
            "fortios",
            "capwap",
            "fabric",
            "heap-overflow",
            "cve-2025-25249",
            "kev",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.1,
            "requires": {
                "tech_hints_any": ["fortinet", "fortios", "fortigate"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "rce_surface", "from_detail": "CAPWAP UDP/5246"},
                ],
                "suggested_followups": [
                    "scanner/http/fortinet_detect",
                ],
            },
        },
    }

    port = OptPort(5246, "CAPWAP control UDP port", True)

    @staticmethod
    def _capwap_discovery() -> bytes:
        # CAPWAP preamble: version 0, type 1 (Discovery Request), hlen=2, wbid=IEEE 802.11
        return struct.pack("!BBBBHHH", 0x10, 0x02, 0x00, 0x01, 0x0000, 0x0000, 0x0000)

    def _udp_probe(self) -> bytes:
        host = self._host()
        port = int(self.port or 5246)
        if not host:
            return b""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(self._timeout())
            sock.sendto(self._capwap_discovery(), (host, port))
            data, _ = sock.recvfrom(4096)
            return data or b""
        except Exception:
            return b""
        finally:
            sock.close()

    def run(self):
        response = self._udp_probe()
        if len(response) < 4:
            return False
        msg_type = response[0] & 0x0F
        if msg_type not in (2, 3, 5):
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2025-25249",
            reason=(
                "CAPWAP control plane responded on UDP/5246 "
                f"(message type {msg_type}) — cw_acd surface exposed"
            ),
            port=int(self.port or 5246),
        )
        return True
