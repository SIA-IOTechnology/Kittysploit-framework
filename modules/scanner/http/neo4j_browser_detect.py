#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Neo4j Browser and HTTP management API."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Neo4j Browser Detection",
        "description": "Detects Neo4j HTTP status/version endpoints and browser UI.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "neo4j", "graph", "database", "panel"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 3,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
        'cost': 1.0,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(7474, "Neo4j HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", required=False)

    def run(self):
        for path in (
            "/db/manage/server/neo4j/status",
            "/db/manage/server/neo4j/version",
            "/user/neo4j",
        ):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            data, err = parse_json_response(r) if r else (None, "bad_status")
            if err or not data:
                continue
            if any(key in data for key in ("neo4j_version", "bolt_direct", "store_id", "version")):
                self.set_info(
                    severity="medium",
                    reason="Neo4j HTTP management API detected",
                    path=path,
                    version=str(data.get("neo4j_version") or data.get("version") or ""),
                )
                return True
        return False
