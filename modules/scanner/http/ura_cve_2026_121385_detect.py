#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-121385 — User Registration Aide password reset."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.user_registration_aide import User_registration_aide


class Module(Scanner, Http_client, User_registration_aide):
    __info__ = {
        "name": "User Registration Aide CVE-2026-121385 detect",
        "description": "Fingerprints user-registration-aide plugin.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-121385"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-121385"],
        "tags": ["wordpress", "ura", "cve-2026-121385"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/ura_cve_2026_121385_password_reset",
                ],
            },
        },
    }

    def run(self):
        ok, version = self.ura_detected()
        if not ok:
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-121385",
            reason=f"User Registration Aide {version or '?'}",
            version=version or "unknown",
        )
        return True