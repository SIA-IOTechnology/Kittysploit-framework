#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect PostgreSQL service via startup handshake."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.postgresql.detectors import probe_postgresql


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "PostgreSQL Info Detection",
        "description": "Detects PostgreSQL via startup handshake and authentication challenge.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "metadata": {"max-request": 1, "product": "postgresql", "vendor": "postgresql"},
        "tags": ["postgresql", "database", "scanner", "enum", "discovery"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(5432, "Target PostgreSQL port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False

        info = probe_postgresql(host=host, port=port, timeout=self._timeout())
        if not info.get("detected"):
            return False

        self.set_info(
            severity="info",
            reason="PostgreSQL service detected",
            auth_required=bool(info.get("auth_required")),
        )
        return True
