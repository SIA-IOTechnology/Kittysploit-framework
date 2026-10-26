#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Wing FTP web client (authenticated RCE chain)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Wing FTP CVE-2025-47812 Detect",
        "description": "Detects Wing FTP web client (authenticated RCE chain).",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2025-47812"],
        "tags": ["scanner", "web", "wing-ftp", "cve-2025-47812"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-47812"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/wing_ftp_cve_2025_47812_rce"],
            },
        },
    }

    def run(self):
        r = self.http_request("GET", "/login.html", allow_redirects=True)
        body = (r.text or "").lower() if r else ""
        if any(m in body for m in ("wing ftp", "wftpserver", "loginok.html")):
            self.set_info(severity="critical", cve="CVE-2025-47812", reason="Wing FTP web UI", confidence="medium")
            return True
        return False
