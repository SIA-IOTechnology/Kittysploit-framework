#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects PDF.js viewer bundles on web apps."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "PDF.js CVE-2024-4367 Detect",
        "description": "Detects PDF.js viewer bundles on web apps.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2024-4367"],
        "tags": ["scanner", "web", "pdfjs", "cve-2024-4367"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-4367"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/pdfjs_cve_2024_4367_rce"],
            },
        },
    }

    def run(self):
        r = self.http_request("GET", "/", allow_redirects=True)
        body = (r.text or "").lower() if r else ""
        if "pdf.js" in body or "pdfjs" in body or "mozilla/pdf" in body:
            self.set_info(severity="high", cve="CVE-2024-4367", reason="PDF.js viewer reference", confidence="low")
            return True
        return False
