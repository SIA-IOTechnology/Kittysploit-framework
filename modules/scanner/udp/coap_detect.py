#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect CoAP services via UDP well-known/core probe."""

from kittysploit import *
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.scanner.coap.detectors import probe_coap


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        "name": "CoAP Service Detection",
        "description": "Detects CoAP endpoints responding to a .well-known/core GET request.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["ics", "iot", "coap", "udp", "scanner", "discovery"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(5683, "CoAP UDP port", True)

    def run(self):
        host = self._host()
        if not host:
            return False

        info = probe_coap(host=host, port=self._port(), timeout=self._timeout())
        if not info.get("detected"):
            return False

        self.set_info(severity="info", reason="CoAP service detected")
        return True
