#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enumerate Payload CMS users, collections, and GraphQL."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.payloadcms_probe import enumerate_payloadcms


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Payload CMS API Enumeration",
        "description": (
            "Probes Payload CMS REST endpoints (/api/users, /api/posts) and GraphQL "
            "for unauthenticated user and collection access."
        ),
        "author": ["KittySploit Team"],
        "tags": ["payloadcms", "cms", "graphql", "enumeration", "auxiliary"],
        "modules": ["scanner/http/payloadcms_detect"],
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

    def run(self):
        findings = enumerate_payloadcms(self.http_request)
        if not findings:
            print_error("No Payload CMS API endpoints accessible")
            return False

        for hit in findings:
            print_success(f"Payload {hit.get('kind')} @ {hit.get('path')}")
            for u in hit.get("sample_users") or []:
                print_info(f"  → {u.get('email')} ({u.get('role')})")

        self.set_info(
            severity="critical" if any(f.get("severity") == "critical" for f in findings) else "high",
            reason=f"Payload CMS enum: {len(findings)} accessible endpoint(s)",
            findings=findings,
        )
        return True
