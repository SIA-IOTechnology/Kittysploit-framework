#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Next."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Next.js <1.2.3 - Open Redirect Detection',
        'description': 'Next.js contains an open redirect via “_next/image” due to improper path parsing.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'redirect', 'nextjs', 'xss', 'vuln'],
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
        'references': [
            'https://github.com/netlify/netlify-ipx/security/advisories/GHSA-9jjv-524m-jm98',
            'https://samcurry.net/universal-xss-on-netlifys-next-js-library/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/_next/image?url=/\\/\\interact.sh/&q=100&w=128&h=128', allow_redirects=False)
        if not r or r.status_code != 308:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('Location: /\\/\\/interact.sh',)
        if (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Next.js <1.2.3 - Open Redirect detected",
                path='/_next/image?url=/\\/\\interact.sh/&q=100&w=128&h=128',
            )
            return True
        return False

