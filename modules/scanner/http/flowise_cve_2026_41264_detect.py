#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-41264 — Flowise CSV Agent prompt injection surface."""

from kittysploit import *
from lib.protocols.http.flowise_client import Flowise
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client, Flowise):
    __info__ = {
        "name": "Flowise CVE-2026-41264 detect",
        "description": "Flowise <= 3.1.2 with public prediction / CSV Agent chatflow exposure.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-41264"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-41264",
            "https://github.com/advisories/GHSA-3HJV-C53M-58JJ",
        ],
        "tags": ["flowise", "csv-agent", "cve-2026-41264"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/flowise_cve_2026_41264_csv_agent_rce",
                ],
            },
        },
    }

    def _vulnerable_version(self, ver: str) -> bool:
        major, minor, patch = self.flowise_version_tuple(ver)
        if major < 3:
            return True
        if major > 3:
            return False
        if minor < 1:
            return True
        if minor == 1 and patch < 3:
            return True
        return False

    def run(self):
        ver = self.flowise_version()
        if not ver or not self._vulnerable_version(ver):
            return False
        cid = self.flowise_public_chatflow_id()
        self.set_info(
            severity="critical",
            cve="CVE-2026-41264",
            version=ver,
            public_chatflow=cid or "unknown",
        )
        return True