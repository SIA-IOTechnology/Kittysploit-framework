#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Laravel Sanctum's SPA authentication uses cookie-based session authentication for first-party single-page appl."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Laravel Sanctum - Stateful Domain CSRF Misconfiguration Detection',
        'description': "Laravel Sanctum's SPA authentication uses cookie-based session authentication for first-party single-page applications. The /sanctum/csrf-cookie endpoint issues XSRF-TOKEN cookies to requesting origins. When SANCTUM_STATEFUL_DOMAINS is misconfigured with wildcard or overly permissive values, the application responds with CORS headers that permit arbitrary external origins to make credentialed cross-origin requests.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'laravel', 'sanctum', 'csrf', 'misconfig', 'cors'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://laravel.com/docs/11.x/sanctum#spa-authentication',
            'https://laravel.com/docs/11.x/sanctum#cors-and-cookies',
        ],
    }

    def run(self):
        path = '/sanctum/csrf-cookie'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Origin': 'https://evil.oast.pro', 'Referer': 'https://evil.oast.pro'})
        if not r or r.status_code not in (200, 204):
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('XSRF-TOKEN',)
        header_regexes = ('(?i)access-control-allow-origin:\\s*https?://evil\\.oast\\.pro', '(?i)access-control-allow-credentials:\\s*true',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, headers) for rx in header_regexes)):
            self.set_info(severity='medium', reason='Laravel Sanctum - Stateful Domain CSRF Misconfiguration detected', path=path)
            return True
        return False

