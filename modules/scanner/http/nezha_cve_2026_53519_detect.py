#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fingerprints Nezha monitoring dashboard/API."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Nezha CVE-2026-53519 Detect",
        "description": "Fingerprints Nezha monitoring dashboard/API.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-53519"],
        "tags": ["scanner", "web", "nezha", "cve-2026-53519"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-53519"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/nezha_cve_2026_53519_jwt_bypass"],
            },
        },
    }

    def run(self):
        for path in ("/", "/dashboard", "/api/v1/version"):
            r = self.http_request("GET", path, allow_redirects=True)
            body = (r.text or "").lower() if r else ""
            if "nezha" in body or "哪吒" in (r.text or ""):
                self.set_info(severity="critical", cve="CVE-2026-53519", reason="Nezha panel/API detected", confidence="medium")
                return True
        return False
