#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GraphQL subscription introspection and alias amplification abuse.

Complements auxiliary/scanner/http/graphql_abuse.py.
"""

from __future__ import annotations

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.graphql_subscription_probe import scan_graphql_subscription_abuse
from lib.scanner.http.module_result import finalize_http_scanner_run, target_base_url


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "GraphQL Subscription / Alias Abuse",
        "description": (
            "Probes GraphQL endpoints for subscription type introspection and alias "
            "amplification (multi-__typename) batching signals."
        ),
        "author": ["KittySploit Team"],
        "tags": ["web", "api", "graphql", "subscription", "scanner", "auxiliary"],
        "modules": ["auxiliary/scanner/http/graphql_abuse", "scanner/http/graphql_detect"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals", "endpoints"],
            "chain": {
                "consumes_capabilities": ["graphql_endpoint"],
                "suggested_followups": ["auxiliary/scanner/http/graphql_abuse"],
            },
        },
    }

    graphql_path = OptString("/graphql", "GraphQL endpoint path", True)

    def run(self):
        path = str(self.graphql_path or "/graphql").strip() or "/graphql"
        print_status(f"GraphQL subscription/alias probe at {path}")
        raw = scan_graphql_subscription_abuse(self.http_request, graphql_path=path)
        if not raw:
            print_warning("No subscription or alias amplification signals")
            return finalize_http_scanner_run(
                self,
                [],
                title="GraphQL subscription abuse",
                severity="info",
                category="api",
                findings_key="graphql_subscription_findings",
            )

        hits = [
            {
                "vulnerable": True,
                "path": path,
                "indicator": item.get("kind"),
                "status_code": 200,
                "subscription_type": item.get("subscription_type"),
                "subscription_fields": item.get("subscription_fields"),
                "alias_count": item.get("alias_count"),
                "content_preview": item.get("preview"),
            }
            for item in raw
        ]
        for hit in hits:
            print_warning(f"GraphQL {hit.get('indicator')} at {path}")

        return finalize_http_scanner_run(
            self,
            hits,
            title="GraphQL subscription / alias abuse",
            severity="medium",
            category="api",
            findings_key="graphql_subscription_findings",
            hit_mapper=lambda hit: {
                "method": "POST",
                "request_url": target_base_url(self, path=str(hit.get("path") or path)),
                "status_code": hit.get("status_code"),
                "evidence_snippet": hit.get("content_preview") or hit.get("indicator"),
                "indicators": [hit.get("indicator")] if hit.get("indicator") else [],
            },
            vulnerability_info_extra={
                "graphql_endpoint": path,
                "subscription_type": hits[0].get("subscription_type") if hits else "",
            },
        )
