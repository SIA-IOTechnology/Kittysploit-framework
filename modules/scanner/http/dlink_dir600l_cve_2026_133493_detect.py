#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-133493 — D-Link DIR-600L genacgi RCE."""

from kittysploit import *
from lib.protocols.http.dlink_dir600l import Dlink_dir600l
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client, Dlink_dir600l):
    __info__ = {
        "name": "D-Link DIR-600L CVE-2026-133493 detect",
        "description": "Fingerprints DIR-600L / genacgi surface.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-133493"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-133493"],
        "tags": ["dlink", "router", "genacgi", "cve-2026-133493"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/linux/http/dlink_dir600l_cve_2026_133493_genacgi_rce",
                ],
            },
        },
    }

    port = OptPort(80, "Router HTTP port", required=False)
    ssl = OptBool(False, "Use HTTPS", required=False, advanced=True)

    def run(self):
        if not self.dir600l_detected():
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-133493",
            reason="D-Link DIR-600L / genacgi",
        )
        return True