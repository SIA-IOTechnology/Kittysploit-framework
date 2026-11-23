#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-129039 — Tribulant Newsletters PHP object injection."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.tribulant_newsletters import Tribulant_newsletters


class Module(Scanner, Http_client, Tribulant_newsletters):
    __info__ = {
        "name": "Tribulant Newsletters CVE-2026-129039 detect",
        "description": "Fingerprints Tribulant Newsletters plugin.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-129039"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-129039"],
        "tags": ["wordpress", "tribulant", "deserialization", "cve-2026-129039"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "auxiliary/admin/http/tribulant_cve_2026_129039_deser_probe",
                ],
            },
        },
    }

    def run(self):
        installed, version = self.newsletters_detected()
        if not installed:
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-129039",
            reason=f"Tribulant Newsletters {version or '?'}",
            version=version or "unknown",
        )
        return True