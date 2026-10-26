#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Next.js Server Actions / middleware headers."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Next.js CVE-2024-34351 Detect",
        "description": "Detects Next.js Server Actions / middleware headers.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2024-34351"],
        "tags": ["scanner", "web", "nextjs", "cve-2024-34351"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-34351"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/nextjs_cve_2024_34351_ssrf"],
            },
        },
    }

    def run(self):
        r = self.http_request("GET", "/", allow_redirects=True)
        body = (r.text or "").lower() if r else ""
        headers = {k.lower(): v for k, v in (dict(getattr(r, "headers", {})) or {}).items()} if r else {}
        if "x-powered-by" in headers and "next" in headers.get("x-powered-by", "").lower():
            self.set_info(severity="high", cve="CVE-2024-34351", reason="Next.js response headers", confidence="medium")
            return True
        if "_next/static" in body:
            self.set_info(severity="high", cve="CVE-2024-34351", reason="Next.js static bundle paths", confidence="medium")
            return True
        return False
