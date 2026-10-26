#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fingerprints motionEye web UI (config API requires signing_key for exploit)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "motionEye CVE-2025-60787 Detect",
        "description": "Fingerprints motionEye web UI (config API requires signing_key for exploit).",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2025-60787"],
        "tags": ["scanner", "web", "motioneye", "cve-2025-60787"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-60787"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/linux/http/motioneye_cve_2025_60787_rce"],
            },
        },
    }
    port = OptPort(8765, "motionEye HTTP port", required=False)

    def run(self):
        for path in ("/", "/config/list"):
            r = self.http_request("GET", path, allow_redirects=True)
            body = (r.text or "").lower() if r else ""
            if "motioneye" in body or (r and int(r.status_code or 0) == 200 and "camera" in body):
                self.set_info(severity="critical", cve="CVE-2025-60787", reason="motionEye UI detected", confidence="medium")
                return True
        return False
