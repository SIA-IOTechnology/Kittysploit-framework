#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IPMI cipher zero auth bypass (NSE ipmi-cipher-zero)."""

from kittysploit import *
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.scanner.ipmi.detectors import probe_ipmi_cipher_zero


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        "name": "IPMI Cipher Zero",
        "description": (
            "Checks whether IPMI 2.0 accepts RMCP+ Open Session with cipher suite 0 "
            "(CVE-2013-4782 authentication bypass — NSE ipmi-cipher-zero)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "references": [
            "https://nmap.org/nsedoc/scripts/ipmi-cipher-zero.html",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-4782",
        ],
        "tags": ["ipmi", "bmc", "cipher-zero", "scanner", "vuln", "udp"],
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
        info = probe_ipmi_cipher_zero(host=host, port=self._port(), timeout=self._timeout())
        if not info.get("vulnerable"):
            return False
        self.set_info(
            severity="critical",
            reason="IPMI cipher suite 0 accepted (auth bypass)",
            error_code=info.get("error_code"),
        )
        return True
