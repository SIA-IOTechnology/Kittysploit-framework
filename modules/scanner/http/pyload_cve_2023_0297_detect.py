#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pyLoad CVE-2023-0297 /flash/addcrypted2 js2py surface."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "pyLoad CVE-2023-0297 Detect",
        "description": "Fingerprints pyLoad UI and /flash/addcrypted2 endpoint.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2023-0297"],
        "tags": ["web", "scanner", "pyload", "cve-2023-0297"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-0297"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints"],
            "chain": {
                "suggested_followups": [
                    "exploits/linux/http/pyload_cve_2023_0297_rce",
                    "scanner/http/pyload_js2py_cve_2024_39205_detect",
                ],
            },
        },
    }

    port = OptPort(8000, "pyLoad web port", required=False)

    def run(self):
        r = self.http_request("GET", "/")
        body = (r.text or "").lower() if r else ""
        if "pyload" not in body:
            r2 = self.http_request("GET", "/flash/addcrypted2")
            if not r2 or int(r2.status_code or 0) >= 404:
                return False
        self.set_info(
            severity="critical",
            cve="CVE-2023-0297",
            reason="pyLoad web UI / addcrypted2 surface",
            confidence="medium",
        )
        return True
