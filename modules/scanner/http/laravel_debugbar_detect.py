#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Laravel Debugbar (barryvdh/laravel-debugbar) was detected as enabled and publicly accessible."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Laravel Debugbar - Sensitive Information Exposure Detection',
        'description': 'Laravel Debugbar (barryvdh/laravel-debugbar) was detected as enabled and publicly accessible. When left active in production, it exposes SQL queries, request data, session variables, mail logs, and application internals to any visitor.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'misconfiguration', 'laravel', 'debugbar', 'misconfig', 'exposure'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/barryvdh/laravel-debugbar',
            'https://laravel.com/docs/10.x/configuration#environment-configuration',
        ],
    }

    def run(self):
        path = '/_debugbar/open'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_any = ('debugbar',)
        ctype_any = ('application/json',)
        if (any(m in body for m in body_any)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='medium',
                reason='Laravel Debugbar - Sensitive Information Exposure detected',
                path=path,
            )
            return True
        return False

