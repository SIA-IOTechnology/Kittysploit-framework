#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects CrushFTP WebInterface (auth bypass user creation chain)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "CrushFTP CVE-2025-31161 Detect",
        "description": "Detects CrushFTP WebInterface (auth bypass user creation chain).",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2025-31161"],
        "tags": ["scanner", "web", "crushftp", "cve-2025-31161"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-31161"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/crushftp_cve_2025_31161_auth_bypass"],
            },
        },
    }
    port = OptPort(8080, "CrushFTP HTTP port", required=False)

    def run(self):
        r = self.http_request("GET", "/WebInterface/", allow_redirects=True)
        body = (r.text or "").lower() if r else ""
        if r and ("crushftp" in body or int(r.status_code or 0) < 500):
            self.set_info(severity="critical", cve="CVE-2025-31161", reason="CrushFTP WebInterface reachable", confidence="medium")
            return True
        return False
