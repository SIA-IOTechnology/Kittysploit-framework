#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-134543 — jprocms DB backup command injection."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.jprocms import Jprocms


class Module(Scanner, Http_client, Jprocms):
    __info__ = {
        "name": "jprocms CVE-2026-134543 detect",
        "description": "Fingerprints jprocms admin surface.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "high",
        "cve": ["CVE-2026-134543"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-134543"],
        "tags": ["jprocms", "command-injection", "cve-2026-134543"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/jprocms_cve_2026_134543_backup_rce",
                ],
            },
        },
    }

    def run(self):
        if not self.jprocms_detected():
            return False
        self.set_info(
            severity="high",
            cve="CVE-2026-134543",
            reason="jprocms installation",
        )
        return True