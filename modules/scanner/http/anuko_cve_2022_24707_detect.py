#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fingerprints Anuko Time Tracker login/register surface."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Anuko Time Tracker CVE-2022-24707 Detect",
        "description": "Fingerprints Anuko Time Tracker login/register surface.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2022-24707"],
        "tags": ["scanner", "web", "anuko", "cve-2022-24707"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-24707"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/anuko_cve_2022_24707_sqli"],
            },
        },
    }

    def run(self):
        r = self.http_request("GET", "/login.php", allow_redirects=True)
        body = (r.text or "").lower() if r else ""
        if "anuko" in body or "time tracker" in body:
            self.set_info(severity="critical", cve="CVE-2022-24707", reason="Anuko Time Tracker detected", confidence="medium")
            return True
        return False
