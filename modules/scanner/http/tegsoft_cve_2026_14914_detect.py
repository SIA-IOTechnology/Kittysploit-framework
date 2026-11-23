#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-14914 — Tegsoft unrestricted file upload."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.tegsoft import Tegsoft


class Module(Scanner, Http_client, Tegsoft):
    __info__ = {
        "name": "Tegsoft CVE-2026-14914 detect",
        "description": "Fingerprints Tegsoft TOBE stack.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-14914"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-14914"],
        "tags": ["tegsoft", "upload", "rce", "cve-2026-14914"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/tegsoft_cve_2026_14914_upload_rce",
                ],
            },
        },
    }

    def run(self):
        if not self.tegsoft_detected():
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-14914",
            reason="Tegsoft / TOBE application",
        )
        return True