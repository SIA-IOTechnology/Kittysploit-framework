#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect NATS messaging servers via INFO handshake."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.nats.detectors import probe_nats


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "NATS Messaging Server Detection",
        "description": "Detects NATS servers by reading the INFO greeting on TCP 4222.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["nats", "messaging", "scanner", "discovery", "tcp"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(4222, "NATS port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        info = probe_nats(host=host, port=port, timeout=self._timeout())
        if not info.get("detected"):
            return False
        auth = bool(info.get("auth_required"))
        self.set_info(
            severity="medium" if not auth else "info",
            reason="NATS server detected"
            + (" (auth_required=false)" if not auth else " (auth required)"),
            version=str(info.get("version") or ""),
            server_id=str(info.get("server_id") or ""),
            auth_required=auth,
            banner=str(info.get("banner") or "")[:300],
        )
        return True
