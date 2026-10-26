#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Adminer database console (elasticsearch plugin LFI chain)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Adminer CVE-2020-35572 Detect",
        "description": "Detects Adminer database console (elasticsearch plugin LFI chain).",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2020-35572"],
        "tags": ["scanner", "web", "adminer", "cve-2020-35572"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-35572"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/adminer_cve_2020_35572_fileread"],
            },
        },
    }

    def run(self):
        for path in ("/adminer.php", "/adminer", "/"):
            r = self.http_request("GET", path, allow_redirects=True)
            body = (r.text or "").lower() if r else ""
            if "adminer" in body and "login" in body:
                self.set_info(severity="high", cve="CVE-2020-35572", reason="Adminer login surface", confidence="medium")
                return True
        return False
