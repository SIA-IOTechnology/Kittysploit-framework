#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-80188 — BuddyBoss Addons auth bypass."""

from kittysploit import *
from lib.protocols.http.buddyboss_addons import Buddyboss_addons
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client, Buddyboss_addons):
    __info__ = {
        "name": "BuddyBoss Addons CVE-2026-80188 detect",
        "description": "Fingerprints BuddyBoss Addons social login handler.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-80188"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-80188"],
        "tags": ["wordpress", "buddyboss", "cve-2026-80188"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/buddyboss_cve_2026_80188_auth_bypass",
                ],
            },
        },
    }

    def run(self):
        ok, version = self.buddyboss_detected()
        if not ok:
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-80188",
            reason=f"BuddyBoss Addons {version or '?'}",
            version=version or "unknown",
        )
        return True