#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Auth0 identity platform tenants."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Auth0 Detection",
        "description": "Detects Auth0 tenants via OIDC metadata and hosted login pages.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "scanner", "auth0", "iam", "oidc", "saas", "panel"],
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
        'chain':         {'produces_capabilities': [{'capability': 'identity_surface', 'from_detail': ''},
                                   {'capability': 'enterprise_panel', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': ['auxiliary/scanner/http/login_page_detector']},
    },
    }

    def run(self):
        host = str(self.target or "").lower()
        if host.endswith(".auth0.com") or ".auth0.com" in host:
            self.set_info(severity="info", reason="Auth0 tenant hostname detected", host=host)
            return True

        for path in ("/.well-known/openid-configuration", "/authorize", "/login"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            data, err = parse_json_response(r) if r else (None, "bad_status")
            if not err and data:
                issuer = str(data.get("issuer") or "").lower()
                if "auth0" in issuer:
                    self.set_info(severity="info", reason="Auth0 OIDC provider detected", path=path)
                    return True
            if r and r.status_code in (200, 302, 401):
                body = (r.text or "").lower()
                headers = {k.lower(): v for k, v in r.headers.items()}
                if "auth0" in body or "auth0" in headers.get("location", "").lower():
                    self.set_info(severity="info", reason="Auth0 login surface detected", path=path)
                    return True
        return False
