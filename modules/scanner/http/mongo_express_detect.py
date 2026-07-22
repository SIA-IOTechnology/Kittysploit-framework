#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect mongo-express MongoDB admin UI."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import is_html_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "mongo-express Detection",
        "description": "Detects mongo-express web UI and public config endpoint.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["web", "scanner", "mongo-express", "mongodb", "panel", "misconfig"],
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
        for path in ("/public/config.js", "/", "/db/admin/"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code not in (200, 401):
                continue
            body = r.text or ""
            if path.endswith("config.js"):
                if "mongoexpress" in body.lower() or "site_baseurl" in body.lower():
                    self.set_info(severity="high", reason="mongo-express config.js exposed", path=path)
                    return True
                continue
            if is_html_response(r) and "mongo express" in body.lower():
                self.set_info(severity="high", reason="mongo-express UI detected", path=path)
                return True
        return False
