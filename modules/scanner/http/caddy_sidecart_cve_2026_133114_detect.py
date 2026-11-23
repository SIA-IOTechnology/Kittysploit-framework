#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-133114 — Caddy WooCommerce Side Cart missing auth."""

from kittysploit import *
from lib.protocols.http.caddy_sidecart import Caddy_sidecart
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client, Caddy_sidecart):
    __info__ = {
        "name": "Caddy Side Cart CVE-2026-133114 detect",
        "description": "Open /wp-json/caddy/v1/saved-items/ without authorization.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "high",
        "cve": ["CVE-2026-133114"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-133114"],
        "tags": ["wordpress", "woocommerce", "caddy", "cve-2026-133114"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "auxiliary/admin/http/caddy_sidecart_cve_2026_133114_data_leak",
                ],
            },
        },
    }

    def run(self):
        if not self.caddy_endpoint_open(1):
            return False
        self.set_info(
            severity="high",
            cve="CVE-2026-133114",
            reason="saved-items REST reachable unauthenticated",
        )
        return True