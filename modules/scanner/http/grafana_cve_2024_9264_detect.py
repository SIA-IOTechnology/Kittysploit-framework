#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Grafana instance (SQL expressions RCE chain)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Grafana CVE-2024-9264 Detect",
        "description": "Detects Grafana instance (SQL expressions RCE chain).",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2024-9264"],
        "tags": ["scanner", "web", "grafana", "cve-2024-9264"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-9264"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/grafana_cve_2024_9264_rce"],
            },
        },
    }

    def run(self):
        r = self.http_request("GET", "/login", allow_redirects=True)
        body = (r.text or "").lower() if r else ""
        if "grafana" in body or (r and int(r.status_code or 0) == 200 and "login" in body):
            self.set_info(severity="critical", cve="CVE-2024-9264", reason="Grafana login surface", confidence="medium")
            return True
        return False
