#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Strapi headless CMS admin and health endpoints."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response, is_html_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Strapi Detection",
        "description": "Detects Strapi CMS admin panel and health API.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "scanner", "strapi", "cms", "nodejs", "panel"],
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
        for path in ("/_health", "/admin", "/admin/init"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r:
                continue
            data, err = parse_json_response(r) if path != "/admin" else (None, "skip")
            if not err and data:
                self.set_info(severity="info", reason="Strapi health API detected", path=path)
                return True
            body = (r.text or "").lower()
            if is_html_response(r) and "strapi" in body and ("admin" in path or "strapi-" in body):
                self.set_info(severity="info", reason="Strapi admin UI detected", path=path)
                return True
        return False
