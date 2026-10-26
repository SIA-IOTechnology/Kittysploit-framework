#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Searchor Flask UI."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Searchor CVE-2023-43364 Detect",
        "description": "Detects Searchor Flask UI.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2023-43364"],
        "tags": ["scanner", "web", "searchor", "cve-2023-43364"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-43364"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/searchor_cve_2023_43364_rce"],
            },
        },
    }
    port = OptPort(8080, "Searchor port", required=False)

    def run(self):
        r = self.http_request("GET", "/", allow_redirects=True)
        body = (r.text or "").lower() if r else ""
        if "searchor" in body:
            self.set_info(severity="critical", cve="CVE-2023-43364", reason="Searchor UI detected", confidence="medium")
            return True
        return False
