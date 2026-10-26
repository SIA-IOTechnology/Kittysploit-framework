#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Bludit admin login (authenticated RCE chain)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Bludit CVE-2019-16113 Detect",
        "description": "Detects Bludit admin login (authenticated RCE chain).",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2019-16113"],
        "tags": ["scanner", "web", "bludit", "cve-2019-16113"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-16113"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/bludit_cve_2019_16113_rce"],
            },
        },
    }

    def run(self):
        r = self.http_request("GET", "/admin/", allow_redirects=True)
        body = (r.text or "").lower() if r else ""
        if "bludit" in body or "bl-login" in body:
            self.set_info(severity="critical", cve="CVE-2019-16113", reason="Bludit admin panel", confidence="medium")
            return True
        return False
