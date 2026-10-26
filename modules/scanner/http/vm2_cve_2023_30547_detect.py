#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Heuristic for Node apps referencing vm2 sandbox (RCE when user code runs)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "vm2 CVE-2023-30547 Detect",
        "description": "Heuristic for Node apps referencing vm2 sandbox (RCE when user code runs).",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2023-30547"],
        "tags": ["scanner", "web", "vm2", "cve-2023-30547"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-30547"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/vm2_cve_2023_30547_rce"],
            },
        },
    }

    def run(self):
        r = self.http_request("GET", "/", allow_redirects=True)
        body = (r.text or "").lower() if r else ""
        if "vm2" in body or "sandbox" in body:
            self.set_info(severity="critical", cve="CVE-2023-30547", reason="vm2/sandbox integration hint", confidence="low")
            return True
        return False
