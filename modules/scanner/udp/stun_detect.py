#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect STUN servers via Binding Request."""

from kittysploit import *
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.scanner.stun.detectors import probe_stun


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        "name": "STUN Service Detection",
        "description": "Detects STUN (RFC 5389) servers with a Binding Request on UDP 3478.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["stun", "webrtc", "udp", "scanner", "discovery", "voip"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(3478, "STUN UDP port", True)

    def run(self):
        host = self._host()
        if not host:
            return False
        info = probe_stun(host=host, port=self._port(), timeout=self._timeout())
        if not info.get("detected"):
            return False
        self.set_info(
            severity="info",
            reason="STUN Binding Response received",
            mapped_address=str(info.get("mapped_address") or ""),
        )
        return True
