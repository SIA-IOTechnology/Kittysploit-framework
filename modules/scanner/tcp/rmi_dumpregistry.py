#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Java RMI registry dump (NSE rmi-dumpregistry)."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.rmi.detectors import probe_rmi_dumpregistry


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "RMI Dump Registry",
        "description": (
            "Performs a JRMP handshake against a Java RMI registry and extracts bound "
            "names when present (NSE rmi-dumpregistry)."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "references": ["https://nmap.org/nsedoc/scripts/rmi-dumpregistry.html"],
        "tags": ["rmi", "java", "scanner", "discovery"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(1099, "RMI registry port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        info = probe_rmi_dumpregistry(host=host, port=port, timeout=self._timeout())
        if not info.get("detected"):
            return False
        names = info.get("names") or []
        self.set_info(
            severity="info",
            reason="Java RMI registry detected",
            names=list(names)[:30],
        )
        return True
