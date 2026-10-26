#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects ISPConfig panel login."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "ISPConfig CVE-2023-46818 Detect",
        "description": "Detects ISPConfig panel login.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2023-46818"],
        "tags": ["scanner", "web", "ispconfig", "cve-2023-46818"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-46818"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/ispconfig_cve_2023_46818_rce"],
            },
        },
    }

    def run(self):
        r = self.http_request("GET", "/login/", allow_redirects=True)
        body = (r.text or "").lower() if r else ""
        if "ispconfig" in body or (r and "ispconfig" in (r.headers.get("Server", "").lower())):
            self.set_info(severity="critical", cve="CVE-2023-46818", reason="ISPConfig panel detected", confidence="medium")
            return True
        return False
