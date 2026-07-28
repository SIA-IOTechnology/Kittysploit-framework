#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reflected cross-site scripting vulnerability was discovered via generic testing."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Reflected XSS Detection',
        'description': 'Reflected cross-site scripting vulnerability was discovered via generic testing. Manual testing is needed to verify exploitation.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'vulnerability', 'xss', 'generic', 'vuln'],
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
                'suggested_followups': [],
            },
        },
    }

    def run(self):
        for path in ('/a%22%3E%3Cinjectable%3E', '/a%27%3E%3Cinjectable%3E'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
            body_any = ('"><injectable>', "'><injectable>", '<title>Access Denied</title>', "You don't have permission to access",)
            ctype_any = ('text/html',)
            if (any(m in body for m in body_any)) and (any(m in content_type for m in ctype_any)):
                self.set_info(
                    severity='low',
                    reason='Reflected XSS detected',
                    path=path,
                )
                return True
        return False

