#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Adminer database administration panel."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import is_html_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Adminer Detection",
        "description": "Detects Adminer single-file DB admin panels.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "scanner", "adminer", "database", "panel"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 4,
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
        'chain':         {'produces_capabilities': [{'capability': 'ssrf_primitive', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    def run(self):
        for path in ("/adminer.php", "/adminer/", "/adminer-4.php", "/_adminer.php"):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r or r.status_code not in (200, 401) or not is_html_response(r):
                continue
            body = (r.text or "").lower()
            if "adminer" in body and ("login" in body or "db=" in body or "driver=" in body):
                self.set_info(severity="info", reason="Adminer panel detected", path=path)
                return True
        return False
