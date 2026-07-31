#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MS17-010 / EternalBlue detection (NSE smb-vuln-ms17-010)."""

from kittysploit import *
from lib.protocols.smb.smb_scanner_client import Smb_scanner_client


class Module(Scanner, Smb_scanner_client):
    __info__ = {
        "name": "SMB MS17-010 (EternalBlue)",
        "description": (
            "Unauthenticated SMBv1 probe for MS17-010 (CVE-2017-0143 / EternalBlue) via "
            "PeekNamedPipe on FID 0 (NSE smb-vuln-ms17-010)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "references": [
            "https://nmap.org/nsedoc/scripts/smb-vuln-ms17-010.html",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143",
        ],
        "tags": ["smb", "ms17-010", "eternalblue", "scanner", "vuln"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    def run(self):
        if not self._host():
            return False
        info = self.ms17_010()
        if not info.get("checked"):
            return False
        if not info.get("vulnerable"):
            # Patched / not vulnerable — still useful signal only if explicitly vulnerable
            return False
        self.set_info(
            severity="critical",
            reason="Host appears vulnerable to MS17-010 (EternalBlue)",
            status_name=str(info.get("status_name") or ""),
            status=hex(int(info["status"])) if info.get("status") is not None else "",
            smb1=bool(info.get("smb1")),
        )
        return True
