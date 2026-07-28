#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect mDNS / DNS-SD responders."""

from kittysploit import *
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.scanner.mdns.detectors import probe_mdns


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        "name": "mDNS / DNS-SD Detection",
        "description": (
            "Queries `_services._dns-sd._udp.local` over unicast mDNS (UDP 5353) "
            "to fingerprint Zeroconf / IoT service advertisements."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["mdns", "dns-sd", "zeroconf", "iot", "udp", "scanner", "discovery"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(5353, "mDNS UDP port", True)

    def run(self):
        host = self._host()
        if not host:
            return False
        info = probe_mdns(host=host, port=self._port(), timeout=self._timeout())
        if not info.get("detected"):
            return False
        services = info.get("services") or []
        self.set_info(
            severity="info",
            reason="mDNS responder detected",
            services=list(services)[:8],
        )
        return True
