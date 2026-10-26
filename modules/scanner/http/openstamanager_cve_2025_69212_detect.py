#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects OpenSTAManager login (authenticated import RCE chain)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "OpenSTAManager CVE-2025-69212 Detect",
        "description": "Detects OpenSTAManager login (authenticated import RCE chain).",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2025-69212"],
        "tags": ["scanner", "web", "openstamanager", "cve-2025-69212"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-69212"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/openstamanager_cve_2025_69212_rce"],
            },
        },
    }

    def run(self):
        r = self.http_request("GET", "/index.php", allow_redirects=True)
        body = (r.text or "").lower() if r else ""
        if ("openstamanager" in body or "osm" in body) and "login" in body:
            self.set_info(severity="critical", cve="CVE-2025-69212", reason="OpenSTAManager login", confidence="medium")
            return True
        return False
