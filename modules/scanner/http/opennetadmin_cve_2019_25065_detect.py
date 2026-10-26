#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects OpenNetAdmin installation."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "OpenNetAdmin CVE-2019-25065 Detect",
        "description": "Detects OpenNetAdmin installation.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2019-25065"],
        "tags": ["scanner", "web", "opennetadmin", "cve-2019-25065"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-25065"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/opennetadmin_cve_2019_25065_rce"],
            },
        },
    }

    def run(self):
        r = self.http_request("GET", "/ona/", allow_redirects=True)
        body = (r.text or "").lower() if r else ""
        if "opennetadmin" in body or "ona" in body:
            self.set_info(severity="critical", cve="CVE-2019-25065", reason="OpenNetAdmin surface", confidence="medium")
            return True
        return False
