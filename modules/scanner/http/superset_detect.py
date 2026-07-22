#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Apache Superset BI dashboard."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import is_html_response, parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Apache Superset Detection",
        "description": "Detects Superset health API and login UI.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "superset", "apache", "bi", "panel"],
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

    def run(self):
        for path in ("/health", "/api/v1/health", "/api/v1/me"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            data, err = parse_json_response(r) if r else (None, "bad_status")
            if not err and data:
                self.set_info(severity="medium", reason="Apache Superset API detected", path=path)
                return True
        r = self.http_request(method="GET", path="/login/", allow_redirects=True)
        if r and not is_html_response(r):
            return False
        body = (r.text or "").lower() if r else ""
        if "superset" in body and ("sign in" in body or "login" in body):
            self.set_info(severity="info", reason="Apache Superset login UI detected")
            return True
        return False
