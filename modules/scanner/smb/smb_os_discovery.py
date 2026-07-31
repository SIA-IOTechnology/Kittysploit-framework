#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SMB OS / domain discovery (NSE smb-os-discovery)."""

from kittysploit import *
from lib.protocols.smb.smb_scanner_client import Smb_scanner_client


class Module(Scanner, Smb_scanner_client):
    __info__ = {
        "name": "SMB OS Discovery",
        "description": (
            "Discovers OS / LAN Manager / domain hints from SMB negotiate and anonymous "
            "session setup (NSE smb-os-discovery)."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "references": ["https://nmap.org/nsedoc/scripts/smb-os-discovery.html"],
        "tags": ["smb", "os", "domain", "scanner", "discovery"],
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
        info = self.os_discovery()
        if not info.get("detected"):
            return False
        os_name = str(info.get("os") or "")
        domain = str(info.get("domain") or "")
        lm = str(info.get("lan_manager") or "")
        server = str(info.get("server") or "")
        if not any((os_name, domain, lm, server)):
            return False
        self.set_info(
            severity="info",
            reason="SMB host identity discovered",
            os=os_name,
            lan_manager=lm,
            domain=domain,
            server=server,
            smb1=bool(info.get("smb1")),
            signing=str(info.get("signing") or ""),
        )
        return True
