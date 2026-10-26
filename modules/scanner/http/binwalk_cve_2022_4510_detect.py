#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Binwalk web admin console (authenticated plugin RCE chain)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Binwalk CVE-2022-4510 Detect",
        "description": "Detects Binwalk web admin console (authenticated plugin RCE chain).",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2022-4510"],
        "tags": ["scanner", "web", "binwalk", "cve-2022-4510"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-4510"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/binwalk_cve_2022_4510_rce"],
            },
        },
    }
    port = OptPort(8080, "Binwalk web port", required=False)

    def run(self):
        r = self.http_request("GET", "/", allow_redirects=True)
        body = (r.text or "").lower() if r else ""
        if "binwalk" in body or (r and int(r.status_code or 0) == 401):
            self.set_info(severity="critical", cve="CVE-2022-4510", reason="Binwalk web admin surface", confidence="low")
            return True
        return False
