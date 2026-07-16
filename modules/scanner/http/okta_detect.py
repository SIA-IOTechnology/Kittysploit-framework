#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Okta identity cloud tenants."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Okta Detection",
        "description": "Detects Okta SSO tenants via OIDC metadata and login UI markers.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "scanner", "okta", "iam", "sso", "saas", "panel"],
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
        if host.endswith(".okta.com") or host.endswith(".oktapreview.com"):
            self.set_info(severity="info", reason="Okta tenant hostname detected", host=host)
            return True

        for path in (
            "/oauth2/default/.well-known/openid-configuration",
            "/.well-known/openid-configuration",
            "/login/login.htm",
        ):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            data, err = parse_json_response(r) if r else (None, "bad_status")
            if not err and data:
                issuer = str(data.get("issuer") or "").lower()
                if "okta" in issuer:
                    self.set_info(severity="info", reason="Okta OIDC provider detected", path=path)
                    return True
            if r and r.status_code in (200, 302):
                body = (r.text or "").lower()
                if "okta" in body and ("sign in" in body or "okta-sign-in" in body):
                    self.set_info(severity="info", reason="Okta login UI detected", path=path)
                    return True
        return False
