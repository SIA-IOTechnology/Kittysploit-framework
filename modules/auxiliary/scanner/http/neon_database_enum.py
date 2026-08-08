#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validate leaked Neon database URLs and Management API keys."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.neon_probe import enumerate_neon
from lib.scanner.http.vibe_secrets_probe import collect_vibe_http_bodies, mask_secret


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Neon Database URL Validation",
        "description": (
            "Parses leaked Neon postgres:// URLs (*.neon.tech) and validates Neon "
            "Management API keys against /api/v2/projects. Auto-discovers from bundles."
        ),
        "author": ["KittySploit Team"],
        "tags": ["neon", "postgres", "database", "cloud", "enumeration", "auxiliary"],
        "modules": [
            "auxiliary/scanner/http/turso_upstash_enum",
            "scanner/http/vibe_stack_secrets_detect",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals", "secret_exposure"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.2,
        },
    }

    database_url = OptString("", "Neon DATABASE_URL (postgres://…@*.neon.tech/…)", False)
    api_key = OptString("", "Neon Management API key", False)
    auto_discover = OptBool(True, "Scrape SPA for Neon credentials", False)

    def run(self):
        bodies = collect_vibe_http_bodies(self.http_request) if self._to_bool(self.auto_discover) else []
        homepage = next((t for p, t in bodies if p == "/"), "")

        self._configure_session()
        findings, creds = enumerate_neon(
            self.session,
            homepage,
            verify_ssl=self._to_bool(self.verify_ssl),
            database_url=str(self.database_url or "").strip(),
            api_key=str(self.api_key or "").strip(),
        )

        ok = [f for f in findings if f.get("ok")]
        if not ok:
            print_error("No Neon credentials found (set DATABASE_URL/API key or enable auto_discover)")
            return False

        for hit in ok:
            print_success(f"Neon {hit.get('kind')}: {hit.get('host') or hit.get('projects') or hit.get('count')}")

        self.set_info(
            severity="critical",
            reason=f"Neon validation: {len(ok)} hit(s)",
            findings=findings,
            credentials={k: mask_secret(v) for k, v in creds.items()},
        )
        return True
