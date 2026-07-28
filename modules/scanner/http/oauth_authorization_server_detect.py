#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects OAuth 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Well-Known OAuth Authorization Server Metadata Detection',
        'description': 'Detects OAuth 2.0 Authorization Server metadata (RFC 8414).',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misc', 'well-known', 'oauth', 'oidc', 'security', 'rfc8414', 'miscellaneous', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0,
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
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [
                    {
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': ['https://www.rfc-editor.org/rfc/rfc8414'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/.well-known/oauth-authorization-server', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        server = r.headers.get("Server") or r.headers.get("server") or ""
        body_all = ('issuer', 'authorization_endpoint',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='info',
                reason="Well-Known OAuth Authorization Server Metadata detected",
                path='/.well-known/oauth-authorization-server',
            )
            return True
        return False

