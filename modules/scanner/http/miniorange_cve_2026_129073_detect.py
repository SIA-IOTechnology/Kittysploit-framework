#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-129073 — miniOrange WordPress auth bypass."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "miniOrange CVE-2026-129073 detect",
        "description": "Fingerprints miniOrange SSO/login plugins.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-129073"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-129073"],
        "tags": ["wordpress", "miniorange", "cve-2026-129073"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/miniorange_cve_2026_129073_auth_bypass",
                ],
            },
        },
    }

    def run(self):
        for path in (
            "/wp-content/plugins/miniorange-saml-20-single-sign-on/readme.txt",
            "/wp-content/plugins/miniorange-login-openid/readme.txt",
        ):
            resp = self.http_request("GET", path)
            if resp and "miniorange" in (resp.text or "").lower():
                self.set_info(severity="critical", cve="CVE-2026-129073", reason="miniOrange plugin")
                return True
        return False