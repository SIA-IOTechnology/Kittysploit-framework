#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Probe Clerk passwordless sign-in strategies via Frontend API."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.clerk_passwordless_probe import enumerate_clerk_passwordless
from lib.scanner.http.vibe_secrets_probe import collect_vibe_http_bodies, mask_secret


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Clerk Passwordless Enumeration",
        "description": (
            "Uses leaked Clerk publishable keys and Frontend API hosts to probe "
            "email_link / email_code passwordless sign-in flows."
        ),
        "author": ["KittySploit Team"],
        "tags": ["clerk", "auth", "passwordless", "magic-link", "enumeration", "auxiliary"],
        "modules": [
            "auxiliary/scanner/http/clerk_auth0_management_enum",
            "scanner/http/magic_link_surface_detect",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe"],
            "expected_requests": 6,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals"],
            "cost": 1.0,
            "noise": 0.5,
            "value": 1.1,
        },
    }

    publishable_key = OptString("", "Clerk publishable key (pk_live_… / pk_test_…)", False)
    frontend_api = OptString("", "Clerk Frontend API host", False)
    probe_email = OptString("security-probe@example.com", "Email for passwordless probe", False, advanced=True)
    auto_discover = OptBool(True, "Scrape SPA for Clerk publishable key", False)

    def run(self):
        bodies = collect_vibe_http_bodies(self.http_request) if self._to_bool(self.auto_discover) else []
        homepage = next((t for p, t in bodies if p == "/"), "")
        if not homepage and bodies:
            homepage = bodies[0][1]

        self._configure_session()
        findings, creds = enumerate_clerk_passwordless(
            self.session,
            homepage,
            verify_ssl=self._to_bool(self.verify_ssl),
            publishable_key=str(self.publishable_key or "").strip(),
            frontend_api=str(self.frontend_api or "").strip(),
            email=str(self.probe_email or "security-probe@example.com").strip(),
        )

        ok = [f for f in findings if f.get("ok")]
        if not ok:
            print_error("No Clerk passwordless surface (set pk_ key or enable auto_discover)")
            return False

        for hit in ok:
            print_success(f"Clerk {hit.get('kind')} via {hit.get('frontend_api')}")

        self.set_info(
            severity="high",
            reason=f"Clerk passwordless: {ok[0].get('kind')}",
            findings=findings,
            credentials={
                k: mask_secret(v) if "key" in k else v for k, v in creds.items()
            },
        )
        return True
