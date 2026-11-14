#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-56274 — Flowise Custom MCP command injection surface."""

from kittysploit import *
from lib.protocols.http.flowise_client import Flowise
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client, Flowise):
    __info__ = {
        "name": "Flowise CVE-2026-56274 detect",
        "description": "Flowise < 3.1.2 Custom MCP server command-flag validation bypass.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-56274"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-56274",
            "https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-m99r-2hxc-cp3q",
        ],
        "tags": ["flowise", "mcp", "cve-2026-56274"],
        "agent": {
            "chain": {
                "suggested_followups": ["exploits/multi/http/flowise_cve_2026_56274_mcp_rce"],
            },
        },
    }

    def run(self):
        ver = self.flowise_version()
        if not ver:
            return False
        major, minor, patch = self.flowise_version_tuple(ver)
        if major > 3 or (major == 3 and minor > 1) or (major == 3 and minor == 1 and patch >= 2):
            return False
        self.set_info(severity="critical", cve="CVE-2026-56274", version=ver)
        return True