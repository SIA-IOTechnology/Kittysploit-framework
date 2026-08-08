#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Probe Auth0 passwordless email link and OTP flows."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.auth0_passwordless_probe import enumerate_auth0_passwordless
from lib.scanner.http.vibe_secrets_probe import collect_vibe_http_bodies, mask_secret


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Auth0 Passwordless Enumeration",
        "description": (
            "Uses leaked Auth0 domain and client_id to probe /passwordless/start "
            "for active email magic-link and OTP flows."
        ),
        "author": ["KittySploit Team"],
        "tags": ["auth0", "auth", "passwordless", "magic-link", "enumeration", "auxiliary"],
        "modules": [
            "auxiliary/scanner/http/clerk_auth0_management_enum",
            "scanner/http/auth0_detect",
            "scanner/http/magic_link_surface_detect",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals"],
            "cost": 1.0,
            "noise": 0.5,
            "value": 1.1,
        },
    }

    auth0_domain = OptString("", "Auth0 tenant domain (tenant.auth0.com)", False)
    auth0_client_id = OptString("", "Auth0 application client ID", False)
    probe_email = OptString("security-probe@example.com", "Email for passwordless probe", False, advanced=True)
    auto_discover = OptBool(True, "Scrape SPA for Auth0 client config", False)

    def run(self):
        bodies = collect_vibe_http_bodies(self.http_request) if self._to_bool(self.auto_discover) else []
        homepage = next((t for p, t in bodies if p == "/"), "")

        self._configure_session()
        findings, creds = enumerate_auth0_passwordless(
            self.session,
            homepage,
            verify_ssl=self._to_bool(self.verify_ssl),
            domain=str(self.auth0_domain or "").strip(),
            client_id=str(self.auth0_client_id or "").strip(),
            email=str(self.probe_email or "security-probe@example.com").strip(),
        )

        ok = [f for f in findings if f.get("ok")]
        if not ok:
            print_error("No Auth0 passwordless access (set domain/client_id or enable auto_discover)")
            return False

        for hit in ok:
            print_success(f"Auth0 {hit.get('kind')} on {hit.get('domain')}")

        self.set_info(
            severity="high",
            reason=f"Auth0 passwordless: {ok[0].get('kind')}",
            findings=findings,
            credentials={k: mask_secret(v) if "client" in k else v for k, v in creds.items()},
        )
        return True
