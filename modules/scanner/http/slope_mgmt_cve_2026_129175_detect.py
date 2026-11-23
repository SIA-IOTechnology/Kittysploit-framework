#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-129175 — Unstable Slope Management missing auth."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.slope_management import Slope_management


class Module(Scanner, Http_client, Slope_management):
    __info__ = {
        "name": "Slope Management CVE-2026-129175 detect",
        "description": "Checks reachability of slope management web UI.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-129175"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-129175"],
        "tags": ["slope", "missing-auth", "cve-2026-129175"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "auxiliary/admin/http/slope_mgmt_cve_2026_129175_unauth_access",
                ],
            },
        },
    }

    def run(self):
        if not self.slope_reachable():
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-129175",
            reason="Slope management service reachable",
        )
        return True