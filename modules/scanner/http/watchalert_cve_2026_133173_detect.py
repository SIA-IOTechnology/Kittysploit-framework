#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-133173 — WatchAlert datasource IDOR."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.watchalert import Watchalert


class Module(Scanner, Http_client, Watchalert):
    __info__ = {
        "name": "WatchAlert CVE-2026-133173 detect",
        "description": "Fingerprints WatchAlert and verifies API login.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "high",
        "cve": ["CVE-2026-133173"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-133173"],
        "tags": ["watchalert", "idor", "cve-2026-133173"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "auxiliary/admin/http/watchalert_cve_2026_133173_ds_leak",
                ],
            },
        },
    }

    username = OptString("", "WatchAlert username", required=True)
    password = OptString("", "WatchAlert password", required=True)
    tenant_id = OptString("", "Workspace / tenant id", required=True)

    def run(self):
        root = self.http_request("GET", "/", timeout=12)
        fp = bool(root and self.watchalert_fingerprint(root.text or ""))
        logged = self.watchalert_login()
        if not logged and not fp:
            return False
        self.set_info(
            severity="high",
            cve="CVE-2026-133173",
            reason="WatchAlert API",
            authenticated=logged,
        )
        return True