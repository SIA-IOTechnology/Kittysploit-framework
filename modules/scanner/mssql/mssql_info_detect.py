#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Microsoft SQL Server via TDS prelogin."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.mssql.detectors import probe_mssql


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "MSSQL Info - Detection",
        "description": "Detects MSSQL via TDS prelogin and reports version and encryption hints.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["mssql", "database", "scanner", "enum", "discovery"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(1433, "Target MSSQL port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False

        info = probe_mssql(host=host, port=port, timeout=self._timeout())
        if not info.get("detected"):
            return False

        version = str(info.get("version_hint") or "unknown")
        encryption = str(info.get("encryption") or "unknown")
        severity = "medium" if encryption == "encryption_off" else "info"
        self.set_info(
            severity=severity,
            reason=f"MSSQL detected ({version}) encryption={encryption}",
            version=version,
            encryption=encryption,
        )
        print_success(f"MSSQL {version} — encryption={encryption}")
        return True
