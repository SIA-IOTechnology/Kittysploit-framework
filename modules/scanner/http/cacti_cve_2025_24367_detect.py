#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fingerprints Cacti graph viewer (authenticated RCE chain)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Cacti CVE-2025-24367 Detect",
        "description": "Fingerprints Cacti graph viewer (authenticated RCE chain).",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2025-24367"],
        "tags": ["scanner", "web", "cacti", "cve-2025-24367"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-24367"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/cacti_cve_2025_24367_rce"],
            },
        },
    }

    def run(self):
        r = self.http_request("GET", "/cacti/", allow_redirects=True)
        body = (r.text or "").lower() if r else ""
        if "cacti" in body or (r and int(r.status_code or 0) in (200, 302)):
            if "cacti" in body or "login" in body:
                self.set_info(severity="critical", cve="CVE-2025-24367", reason="Cacti web UI", confidence="medium")
                return True
        return False
