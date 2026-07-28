#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect SSDP / UPnP responders."""

from kittysploit import *
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.scanner.ssdp.detectors import probe_ssdp


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        "name": "SSDP / UPnP Detection",
        "description": "Sends a unicast SSDP M-SEARCH to detect UPnP devices on UDP 1900.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["ssdp", "upnp", "iot", "udp", "scanner", "discovery"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
        },
    }

    port = OptPort(1900, "SSDP UDP port", True)

    def run(self):
        host = self._host()
        if not host:
            return False
        info = probe_ssdp(host=host, port=self._port(), timeout=self._timeout())
        if not info.get("detected"):
            return False
        self.set_info(
            severity="info",
            reason="SSDP/UPnP responder detected",
            st=str(info.get("st") or ""),
            server=str(info.get("server") or ""),
            location=str(info.get("location") or ""),
            usn=str(info.get("usn") or ""),
        )
        return True
