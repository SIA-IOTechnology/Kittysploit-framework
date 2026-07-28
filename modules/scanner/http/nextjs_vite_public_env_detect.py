#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Identified public environment variables exposed to the client in Next."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Next.js / Vite Public ENV Exposure Detection',
        'description': 'Identified public environment variables exposed to the client in Next.js (__NEXT_DATA__.env) and Vite applications through runtime configurations. Extended to detect any exposed Supabase URL on the page, regardless of variable name.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'exposure', 'env', 'nextjs', 'vite', 'supabase', 'vuln'],
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
            'https://nextjs.org/docs/app/building-your-application/configuring/environment-variables',
            'https://vite.dev/guide/env-and-mode.html',
            'https://supabase.com/docs/guides/api#api-keys',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('(?i)"NEXT_PUBLIC_SUPABASE_URL"\\s*:\\s*"https?://[a-z0-9\\.\\-:/]+"', '(?i)"NEXT_PUBLIC_SUPABASE_ANON_KEY"\\s*:\\s*"[A-Za-z0-9\\.\\-_]{20,}"', '(?i)\\bVITE_SUPABASE_URL\\b"\\s*:\\s*"https?://[a-z0-9\\.\\-:/]+"', '(?i)\\bVITE_SUPABASE_ANON_KEY\\b"\\s*:\\s*"[A-Za-z0-9\\.\\-_]{20,}"', '(?i)window\\.__env\\s*=\\s*\\{[^}]*?(SUPABASE_(URL|ANON_KEY))[^}]*?\\}', '(?i)__NEXT_DATA__.*?"env"\\s*:\\s*\\{[^}]*?NEXT_PUBLIC_[A-Z0-9_]{2,}', '(?i)\\bVITE_[A-Z0-9_]{2,}"\\s*:\\s*"[^"]{3,}',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="Next.js / Vite Public ENV Exposure detected",
                path='/',
            )
            return True
        return False

