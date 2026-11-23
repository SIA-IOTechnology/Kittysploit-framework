#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-133117 — WooCommerce Product Feeds cron salt."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.woo_product_feeds import Woo_product_feeds, DEFAULT_SALT


class Module(Scanner, Http_client, Woo_product_feeds):
    __info__ = {
        "name": "Woo Product Feeds CVE-2026-133117 detect",
        "description": "Fingerprints woocommerce-product-feeds plugin.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-133117"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-133117"],
        "tags": ["wordpress", "woocommerce", "cve-2026-133117"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "auxiliary/admin/http/woo_product_feeds_cve_2026_133117_cron_trigger",
                ],
            },
        },
    }

    def run(self):
        if not self.woo_feeds_detected():
            return False
        nonce = self.woo_feeds_nonces(DEFAULT_SALT)[0]
        self.set_info(
            severity="critical",
            cve="CVE-2026-133117",
            reason="woocommerce-product-feeds installed",
            cron_nonce_hint=nonce[:12],
        )
        return True