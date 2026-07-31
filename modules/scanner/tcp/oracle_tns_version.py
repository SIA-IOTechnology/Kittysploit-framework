#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Oracle TNS version (NSE oracle-tns-version)."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.oracle.detectors import probe_oracle_tns_version


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "Oracle TNS Version",
        "description": (
            "Queries Oracle TNS Listener for version/banner information "
            "(NSE oracle-tns-version)."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "references": ["https://nmap.org/nsedoc/scripts/oracle-tns-version.html"],
        "tags": ["oracle", "tns", "database", "scanner", "discovery"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(1521, "Oracle TNS port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        info = probe_oracle_tns_version(host=host, port=port, timeout=self._timeout())
        if not info.get("detected"):
            return False
        self.set_info(
            severity="info",
            reason="Oracle TNS listener detected",
            version=str(info.get("version") or ""),
            banner=str(info.get("banner") or "")[:200],
        )
        return True
