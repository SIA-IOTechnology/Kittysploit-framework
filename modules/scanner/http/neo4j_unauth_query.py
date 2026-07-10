#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verify unauthenticated Neo4j Cypher queries."""

import json

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Neo4j Unauthenticated Query Verification",
        "description": "Confirms anonymous Neo4j HTTP transaction commits with RETURN 1.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["neo4j", "database", "graph", "scanner", "unauth", "verify"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {"produces_capabilities": ["db_access", "unauth_read"]},
        },
    }

    port = OptPort(7474, "Neo4j HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", required=False)

    def run(self):
        payload = {"statements": [{"statement": "RETURN 1 AS ok"}]}
        body = json.dumps(payload)
        for path in ("/db/data/transaction/commit", "/db/neo4j/tx/commit"):
            r = self.http_request(
                method="POST",
                path=path,
                data=body,
                headers={"Content-Type": "application/json"},
                allow_redirects=False,
            )
            data, err = parse_json_response(r) if r else (None, "bad_status")
            if err or not data:
                continue
            errors = data.get("errors") or []
            results = data.get("results") or []
            if results and not errors:
                self.set_info(
                    severity="high",
                    reason="Neo4j executed unauthenticated Cypher query",
                    path=path,
                    confidence="high",
                )
                return True
        return False
