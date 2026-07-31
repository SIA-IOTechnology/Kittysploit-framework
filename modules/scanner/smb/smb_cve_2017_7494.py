#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SambaCry CVE-2017-7494 version check (NSE smb-vuln-cve-2017-7494 check-version)."""

from kittysploit import *
from lib.protocols.smb.smb_scanner_client import Smb_scanner_client


class Module(Scanner, Smb_scanner_client):
    __info__ = {
        "name": "Samba CVE-2017-7494 (version check)",
        "description": (
            "Non-intrusive SambaCry likelihood check based on disclosed Samba version "
            "(NSE smb-vuln-cve-2017-7494 check-version mode). Does not upload libraries."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "references": [
            "https://nmap.org/nsedoc/scripts/smb-vuln-cve-2017-7494.html",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7494",
        ],
        "tags": ["smb", "samba", "cve-2017-7494", "sambacry", "scanner", "vuln"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    def run(self):
        if not self._host():
            return False
        info = self.samba_cve_2017_7494()
        if not info.get("checked") or not info.get("likely_vulnerable"):
            return False
        self.set_info(
            severity="high",
            reason="Samba version in CVE-2017-7494 vulnerable range",
            samba_version=str(info.get("samba_version") or ""),
            os=str(info.get("os") or "")[:120],
        )
        return True
