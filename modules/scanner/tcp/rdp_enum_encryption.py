#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RDP encryption / NLA negotiation enum (NSE rdp-enum-encryption)."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.rdp.detectors import probe_rdp_encryption


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "RDP Encryption Enumeration",
        "description": (
            "Negotiates RDP security protocols and reports SSL / CredSSP (NLA) / RDSTLS "
            "selection (NSE rdp-enum-encryption)."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "references": ["https://nmap.org/nsedoc/scripts/rdp-enum-encryption.html"],
        "tags": ["rdp", "windows", "nla", "scanner", "discovery"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(3389, "RDP port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        info = probe_rdp_encryption(host=host, port=port, timeout=self._timeout())
        if not info.get("detected"):
            return False
        flags = info.get("selected_flags") or []
        severity = "info"
        if not info.get("nla") and "PROTOCOL_SSL" in flags:
            severity = "low"
        self.set_info(
            severity=severity,
            reason="RDP protocol negotiation completed",
            selected_protocol=str(info.get("selected_protocol") or ""),
            protocols=list(flags),
            nla=bool(info.get("nla")),
            failure_code=info.get("failure_code"),
        )
        return True
