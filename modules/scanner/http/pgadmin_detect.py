#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect pgAdmin PostgreSQL web console."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import is_html_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "pgAdmin Detection",
        "description": "Detects pgAdmin4 browser UI and misc/ping endpoint.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "scanner", "pgadmin", "postgresql", "panel"],
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
        r = self.http_request(method="GET", path="/misc/ping", allow_redirects=False)
        if r and r.status_code == 200 and str(r.text or "").strip().upper() == "PONG":
            self.set_info(severity="info", reason="pgAdmin misc/ping responded PONG")
            return True
        for path in ("/browser/", "/login"):
            resp = self.http_request(method="GET", path=path, allow_redirects=True)
            if not resp or not is_html_response(resp):
                continue
            body = (resp.text or "").lower()
            if "pgadmin" in body:
                self.set_info(severity="info", reason="pgAdmin UI detected", path=path)
                return True
        return False
