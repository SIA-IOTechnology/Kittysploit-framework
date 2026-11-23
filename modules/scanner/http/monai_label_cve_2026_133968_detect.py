#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-133968 — MONAI Label path traversal."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.monai_label import Monai_label


class Module(Scanner, Http_client, Monai_label):
    __info__ = {
        "name": "MONAI Label CVE-2026-133968 detect",
        "description": "Fingerprints MONAI Label service.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-133968"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-133968"],
        "tags": ["monai", "path-traversal", "cve-2026-133968"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "auxiliary/admin/http/monai_label_cve_2026_133968_traversal_read",
                ],
            },
        },
    }

    port = OptPort(8000, "MONAI Label HTTP port", required=False)

    def run(self):
        if not self.monai_detected():
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-133968",
            reason="MONAI Label API detected",
        )
        return True