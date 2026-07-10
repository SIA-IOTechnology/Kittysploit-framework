#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Cassandra CQL native protocol on TCP 9042."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.cassandra.detectors import probe_cassandra_native


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "Cassandra Native Protocol Detection",
        "description": "Detects Cassandra via CQL native protocol OPTIONS/SUPPORTED handshake.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "metadata": {"max-request": 1, "product": "cassandra", "vendor": "apache"},
        "tags": ["cassandra", "database", "scanner", "discovery"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(9042, "Cassandra CQL port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        info = probe_cassandra_native(host=host, port=port, timeout=self._timeout())
        if not info.get("detected"):
            return False
        self.set_info(
            severity="info",
            reason="Cassandra CQL native protocol detected",
            cql_hint=str(info.get("cql_version") or ""),
        )
        return True
