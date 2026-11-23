#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-129056 — Authorizer privilege escalation."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wp_authorizer import Wp_authorizer


class Module(Scanner, Http_client, Wp_authorizer):
    __info__ = {
        "name": "Authorizer CVE-2026-129056 detect",
        "description": "Fingerprints Authorizer WordPress plugin.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-129056"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-129056"],
        "tags": ["wordpress", "authorizer", "cve-2026-129056"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/wp_authorizer_cve_2026_129056_privesc",
                ],
            },
        },
    }

    def run(self):
        ok, version = self.authorizer_detected()
        if not ok:
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-129056",
            reason=f"Authorizer {version or '?'}",
            version=version or "unknown",
        )
        return True