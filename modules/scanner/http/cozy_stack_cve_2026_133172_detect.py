#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-133172 — cozy-stack shared drive move bypass."""

from kittysploit import *
from lib.protocols.http.cozy_stack import Cozy_stack
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client, Cozy_stack):
    __info__ = {
        "name": "cozy-stack CVE-2026-133172 detect",
        "description": "Fingerprints cozy-stack and verifies API with token.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "high",
        "cve": ["CVE-2026-133172"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-133172"],
        "tags": ["cozy", "idor", "cve-2026-133172"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "auxiliary/admin/http/cozy_stack_cve_2026_133172_drive_move",
                ],
            },
        },
    }

    api_token = OptString("", "cozy-stack bearer token (optional for API check)", required=False)

    def run(self):
        root = self.http_request("GET", "/", timeout=12)
        fp = bool(root and self.cozy_fingerprint(root.text or ""))
        token = str(self.api_token or "").strip()
        if hasattr(self, "api_token") and hasattr(self.api_token, "value"):
            token = str(self.api_token.value or "").strip()
        api_ok = False
        if token:
            api_ok, code = self.cozy_instance_ok()
            fp = fp or api_ok
        if not fp:
            return False
        self.set_info(
            severity="high",
            cve="CVE-2026-133172",
            reason="cozy-stack instance",
            api_reachable=api_ok,
        )
        return True