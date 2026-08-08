#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test Stripe webhook endpoints with leaked whsec signing secrets."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.stripe_webhook_probe import enumerate_stripe_webhooks
from lib.scanner.http.vibe_secrets_probe import collect_vibe_http_bodies, mask_secret


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Stripe Webhook Secret Abuse",
        "description": (
            "Discovers whsec_* webhook secrets and probes common Stripe webhook paths. "
            "Tests unsigned acceptance and HMAC-signed delivery with leaked secrets."
        ),
        "author": ["KittySploit Team"],
        "tags": ["stripe", "webhook", "payment", "enumeration", "auxiliary"],
        "modules": [
            "scanner/http/vibe_stack_secrets_detect",
            "scanner/http/preview_deploy_prod_secrets_detect",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe"],
            "expected_requests": 8,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
            "cost": 1.1,
            "noise": 0.5,
            "value": 1.3,
        },
    }

    whsec = OptString("", "Stripe webhook signing secret (whsec_…)", False)
    auto_discover = OptBool(True, "Scrape SPA for Stripe webhook secrets", False)

    def run(self):
        bodies = collect_vibe_http_bodies(self.http_request) if self._to_bool(self.auto_discover) else []
        homepage = next((t for p, t in bodies if p == "/"), "")

        findings, creds = enumerate_stripe_webhooks(
            self.http_request,
            homepage,
            whsec=str(self.whsec or "").strip(),
        )

        hits = [f for f in findings if f.get("kind") != "stripe_whsec_discovered" or creds.get("whsec")]
        critical = [f for f in findings if f.get("severity") == "critical"]
        if not hits:
            print_error("No Stripe webhook signals (set whsec or enable auto_discover)")
            return False

        for hit in hits:
            if hit.get("path"):
                print_success(f"Stripe {hit.get('kind')} @ {hit.get('path')}")
            else:
                print_success(f"Stripe {hit.get('kind')}")

        self.set_info(
            severity="critical" if critical else "high",
            reason=f"Stripe webhook abuse: {len(hits)} signal(s)",
            findings=findings,
            credentials={k: mask_secret(v) for k, v in creds.items()},
        )
        return True
