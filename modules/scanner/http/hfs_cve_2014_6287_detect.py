#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects HttpFileServer (HFS) web UI."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "HFS CVE-2014-6287 Detect",
        "description": "Detects HttpFileServer (HFS) web UI.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2014-6287"],
        "tags": ["scanner", "web", "hfs", "cve-2014-6287"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2014-6287"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/hfs_cve_2014_6287_rce"],
            },
        },
    }
    port = OptPort(80, "HFS HTTP port", required=False)

    def run(self):
        r = self.http_request("GET", "/", allow_redirects=True)
        body = (r.text or "").lower() if r else ""
        if "httpfileserver" in body or "hfs" in body:
            self.set_info(severity="critical", cve="CVE-2014-6287", reason="HttpFileServer UI detected", confidence="medium")
            return True
        return False
