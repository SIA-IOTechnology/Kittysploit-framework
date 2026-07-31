#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NetBIOS node status (NSE nbstat)."""

from kittysploit import *
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.scanner.netbios.detectors import probe_nbstat


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        "name": "NetBIOS NBSTAT",
        "description": (
            "Queries NetBIOS node status (UDP/137) for registered names and MAC "
            "(NSE nbstat)."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "references": ["https://nmap.org/nsedoc/scripts/nbstat.html"],
        "tags": ["netbios", "nbstat", "nbns", "windows", "scanner", "udp", "discovery"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(137, "NetBIOS name service UDP port", True)

    def run(self):
        host = self._host()
        if not host:
            return False
        info = probe_nbstat(host=host, port=self._port(), timeout=self._timeout())
        if not info.get("detected"):
            return False
        names = info.get("names") or []
        self.set_info(
            severity="info",
            reason=f"NetBIOS node status ({len(names)} names)",
            names=names[:32],
            mac=str(info.get("mac") or ""),
        )
        return True
