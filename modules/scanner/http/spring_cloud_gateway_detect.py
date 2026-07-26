#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed Spring Cloud Gateway actuator routes."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Spring Cloud Gateway Detection",
        "description": "Detects exposed Spring Cloud Gateway route definitions via Actuator.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["web", "scanner", "spring", "gateway", "actuator", "java", "misconfig"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
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

    def run(self):
        for path in ("/actuator/gateway/routes", "/gateway/routes"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            data, err = parse_json_response(r) if r else (None, "bad_status")
            if err or not data:
                continue
            if isinstance(data, list) and data:
                count = len(data)
            elif isinstance(data, dict):
                routes = data.get("routes")
                if isinstance(routes, list):
                    count = len(routes)
                elif any(isinstance(value, dict) and "uri" in value for value in data.values()):
                    count = len(data)
                else:
                    continue
            else:
                continue
            self.set_info(
                severity="high",
                reason="Spring Cloud Gateway routes exposed",
                path=path,
                route_count=count,
            )
            return True
        return False
