#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-120681 — Mang Board authorization bypass."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.mangboard import Mangboard


class Module(Scanner, Http_client, Mangboard):
    __info__ = {
        "name": "Mang Board CVE-2026-120681 detect",
        "description": "Fingerprints Mang Board and probes privileged AJAX without auth.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-120681"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-120681"],
        "tags": ["wordpress", "mangboard", "cve-2026-120681"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/mangboard_cve_2026_120681_auth_bypass",
                ],
            },
        },
    }

    ajax_action = OptString("mangboard_admin", "Privileged admin-ajax action", required=False)

    def run(self):
        installed, version = self.mangboard_detected()
        if not installed:
            return False
        action = str(self.ajax_action or "mangboard_admin")
        code, _, ok = self.mangboard_invoke(action)
        if ok:
            reason = f"Mang Board {version or '?'} action {action} unauth (HTTP {code})"
        else:
            reason = f"Mang Board {version or '?'} installed"
        self.set_info(
            severity="critical",
            cve="CVE-2026-120681",
            reason=reason,
            version=version or "unknown",
            unauth_action=ok,
        )
        return True