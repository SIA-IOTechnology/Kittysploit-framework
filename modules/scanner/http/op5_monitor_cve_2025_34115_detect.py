#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects OP5 Monitor / ITRS login surface."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "OP5 Monitor CVE-2025-34115 Detect",
        "description": "Detects OP5 Monitor / ITRS login surface.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2025-34115"],
        "tags": ["scanner", "web", "op5", "cve-2025-34115"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-34115"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/op5_monitor_cve_2025_34115_rce"],
            },
        },
    }

    def run(self):
        r = self.http_request("GET", "/monitor/", allow_redirects=True)
        body = (r.text or "").lower() if r else ""
        if "op5" in body or "itrs" in body or "monitor" in body:
            self.set_info(severity="critical", cve="CVE-2025-34115", reason="OP5/ITRS monitor UI hint", confidence="low")
            return True
        return False
