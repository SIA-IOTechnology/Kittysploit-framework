#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect TURN / coturn servers via Allocate Request."""

from kittysploit import *
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.scanner.turn.detectors import probe_turn


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        "name": "TURN / coturn Service Detection",
        "description": (
            "Detects TURN (RFC 5766) and coturn by sending an Allocate Request on UDP 3478."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["turn", "coturn", "stun", "webrtc", "udp", "scanner", "discovery"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(3478, "TURN UDP port", True)

    def run(self):
        host = self._host()
        if not host:
            return False
        info = probe_turn(host=host, port=self._port(), timeout=self._timeout())
        if not info.get("detected"):
            return False
        software = str(info.get("software") or "")
        coturn = bool(info.get("coturn"))
        self.set_info(
            severity="info",
            reason=("coturn TURN service detected" if coturn else "TURN service detected"),
            software=software,
            realm=str(info.get("realm") or ""),
            error_code=info.get("error_code"),
            coturn=coturn,
        )
        return True
