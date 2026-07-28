#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect WireGuard endpoints via handshake probe on UDP 51820."""

from kittysploit import *
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.scanner.wireguard.detectors import probe_wireguard


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        "name": "WireGuard Handshake Detection",
        "description": (
            "Best-effort WireGuard detection by sending a Handshake Initiation on UDP 51820. "
            "Silent drops are common without a matching peer key."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["wireguard", "vpn", "udp", "scanner", "discovery"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(51820, "WireGuard UDP port", True)

    def run(self):
        host = self._host()
        if not host:
            return False
        info = probe_wireguard(host=host, port=self._port(), timeout=self._timeout())
        if not info.get("detected"):
            return False
        self.set_info(
            severity="info",
            reason="WireGuard-shaped UDP response received",
            message_type=info.get("message_type"),
            response_len=info.get("response_len"),
        )
        return True
