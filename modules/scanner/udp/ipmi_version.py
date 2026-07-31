#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IPMI version fingerprint (NSE ipmi-version)."""

from kittysploit import *
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.scanner.ipmi.detectors import probe_ipmi_version


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        "name": "IPMI Version",
        "description": (
            "Probes IPMI/RMCP Get Channel Authentication Capabilities on UDP/623 "
            "(NSE ipmi-version)."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "references": ["https://nmap.org/nsedoc/scripts/ipmi-version.html"],
        "tags": ["ipmi", "bmc", "rmcp", "udp", "scanner", "discovery"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(623, "IPMI RMCP UDP port", True)

    def run(self):
        host = self._host()
        if not host:
            return False
        info = probe_ipmi_version(host=host, port=self._port(), timeout=self._timeout())
        if not info.get("detected"):
            return False
        self.set_info(
            severity="info",
            reason="IPMI/RMCP service detected",
            ipmi_version=str(info.get("ipmi_version") or ""),
            auth_types=list(info.get("auth_types") or []),
        )
        return True
