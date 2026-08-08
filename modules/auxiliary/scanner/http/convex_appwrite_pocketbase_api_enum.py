#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enumerate Convex, Appwrite, and PocketBase APIs from discovered credentials.

Follow-up for vibe_stack_secrets_detect and panel detectors.
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.baas_api_probe import discover_baas_credentials, enumerate_baas_targets
from lib.scanner.http.vibe_secrets_probe import collect_vibe_http_bodies


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Convex / Appwrite / PocketBase API Enumeration",
        "description": (
            "Enumerates PocketBase /api/collections, Appwrite /v1 databases, and Convex "
            "deployments discovered in client bundles. Auto-scrapes credentials when omitted."
        ),
        "author": ["KittySploit Team"],
        "tags": [
            "convex",
            "appwrite",
            "pocketbase",
            "baas",
            "enumeration",
            "cloud",
            "misconfig",
            "auxiliary",
            "nocode",
        ],
        "modules": [
            "scanner/http/pocketbase_detect",
            "scanner/http/appwrite_detect",
            "scanner/http/vibe_stack_secrets_detect",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe", "data_exfiltration"],
            "expected_requests": 12,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals", "exploit_paths"],
            "cost": 1.2,
            "noise": 0.4,
            "value": 1.2,
        },
    }

    appwrite_project = OptString("", "Appwrite project ID (optional)", False)
    auto_discover = OptBool(True, "Scrape SPA for BaaS credentials", False)

    def run(self):
        bodies = collect_vibe_http_bodies(self.http_request)
        homepage = next((t for p, t in bodies if p == "/"), "")
        creds = discover_baas_credentials(homepage)
        if str(self.appwrite_project or "").strip():
            creds["appwrite_project"] = str(self.appwrite_project).strip()

        findings, discovered = enumerate_baas_targets(self.http_request, homepage_html=homepage)
        if not findings:
            print_warning("No BaaS enumeration results (PocketBase/Appwrite/Convex)")
            return False

        platforms = sorted({str(f.get("platform") or "?") for f in findings})
        print_success(f"BaaS enum: {', '.join(platforms)} — {len(findings)} result(s)")
        for item in findings[:8]:
            print_info(f"  [{item.get('platform')}] {item.get('kind')} @ {item.get('path', item.get('deployment', '?'))}")

        self.set_info(
            severity="high",
            reason=f"BaaS API enumeration: {', '.join(platforms)}",
            findings=findings[:25],
            credentials=discovered,
        )
        return True
