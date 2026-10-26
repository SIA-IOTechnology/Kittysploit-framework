#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects SQLPad web console."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "SQLPad CVE-2022-0944 Detect",
        "description": "Detects SQLPad web console.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2022-0944"],
        "tags": ["scanner", "web", "sqlpad", "cve-2022-0944"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-0944"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/sqlpad_cve_2022_0944_rce"],
            },
        },
    }
    port = OptPort(3000, "SQLPad port", required=False)

    def run(self):
        r = self.http_request("GET", "/", allow_redirects=True)
        body = (r.text or "").lower() if r else ""
        if "sqlpad" in body or (r and int(r.status_code or 0) == 200 and "sign in" in body):
            self.set_info(severity="critical", cve="CVE-2022-0944", reason="SQLPad console detected", confidence="medium")
            return True
        return False
