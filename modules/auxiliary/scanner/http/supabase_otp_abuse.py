#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Abuse Supabase Auth OTP and magic link endpoints using leaked anon keys."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.supabase_otp_probe import enumerate_supabase_otp
from lib.scanner.http.vibe_secrets_probe import collect_vibe_http_bodies


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Supabase OTP / Magic Link Abuse",
        "description": (
            "Uses leaked Supabase anon keys to probe /auth/v1/otp and /auth/v1/magiclink "
            "for active passwordless flows. Auto-discovers project ref and keys from bundles."
        ),
        "author": ["KittySploit Team"],
        "tags": ["supabase", "auth", "otp", "magic-link", "enumeration", "auxiliary"],
        "modules": [
            "scanner/http/supabase_key_exposure_detect",
            "auxiliary/scanner/http/supabase_api_enum",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals"],
            "cost": 1.0,
            "noise": 0.5,
            "value": 1.1,
        },
    }

    project_ref = OptString("", "Supabase project ref (subdomain)", False)
    anon_key = OptString("", "Supabase anon JWT key", False)
    probe_email = OptString("security-probe@example.com", "Email used for OTP probe", False, advanced=True)
    auto_discover = OptBool(True, "Scrape SPA for Supabase credentials", False)

    def run(self):
        bodies = collect_vibe_http_bodies(self.http_request) if self._to_bool(self.auto_discover) else []
        homepage = next((t for p, t in bodies if p == "/"), "")
        if not homepage and bodies:
            homepage = bodies[0][1]

        self._configure_session()
        findings, creds = enumerate_supabase_otp(
            self.session,
            homepage,
            verify_ssl=self._to_bool(self.verify_ssl),
            project_ref=str(self.project_ref or "").strip(),
            anon_key=str(self.anon_key or "").strip(),
            email=str(self.probe_email or "security-probe@example.com").strip(),
        )

        ok = [f for f in findings if f.get("ok")]
        if not ok:
            print_error("No Supabase OTP/magic-link access (set options or enable auto_discover)")
            return False

        for hit in ok:
            print_success(f"Supabase {hit.get('kind')} — HTTP {hit.get('status_code')}")

        self.set_info(
            severity="high",
            reason=f"Supabase OTP enum: {len(ok)} active auth endpoint(s)",
            findings=findings,
            project_ref=creds.get("project_ref"),
        )
        return True
