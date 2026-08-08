#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enumerate PocketBase admin surfaces and collections."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.pocketbase_probe import enumerate_pocketbase
from lib.scanner.http.vibe_secrets_probe import collect_vibe_http_bodies, mask_secret


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "PocketBase Admin Enumeration",
        "description": (
            "Probes PocketBase /api/collections, /api/settings, and authenticates with "
            "leaked admin credentials to enumerate admin API surfaces."
        ),
        "author": ["KittySploit Team"],
        "tags": ["pocketbase", "baas", "admin", "enumeration", "auxiliary"],
        "modules": [
            "scanner/http/pocketbase_detect",
            "auxiliary/scanner/http/convex_appwrite_pocketbase_api_enum",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe", "data_exfiltration"],
            "expected_requests": 10,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.2,
        },
    }

    admin_email = OptString("", "PocketBase admin email", False)
    admin_password = OptString("", "PocketBase admin password", False)
    auto_discover = OptBool(True, "Scrape SPA for PocketBase admin credentials", False)

    def run(self):
        bodies = collect_vibe_http_bodies(self.http_request) if self._to_bool(self.auto_discover) else []
        homepage = next((t for p, t in bodies if p == "/"), "")

        findings, creds = enumerate_pocketbase(
            self.http_request,
            homepage,
            admin_email=str(self.admin_email or "").strip(),
            admin_password=str(self.admin_password or "").strip(),
        )

        hits = [f for f in findings if f.get("severity") in ("critical", "high") or f.get("ok")]
        if not hits:
            print_error("No PocketBase admin/collection access")
            return False

        for hit in hits:
            print_success(f"PocketBase {hit.get('kind')} @ {hit.get('path', '?')}")

        self.set_info(
            severity="critical" if any(f.get("severity") == "critical" for f in hits) else "high",
            reason=f"PocketBase enum: {len(hits)} hit(s)",
            findings=findings,
            credentials={k: mask_secret(v) if "password" in k or "email" in k else v for k, v in creds.items()},
        )
        return True
