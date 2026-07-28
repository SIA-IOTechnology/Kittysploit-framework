#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Adminer <= 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Adminer 4.6.2 - 5.4.1 Unauthenticated Persistent DoS Detection',
        'description': 'Adminer <= 5.4.1 contains a denial of service caused by lack of origin validation in version check endpoint, letting attackers trigger server errors via crafted POST requests, exploit requires no special privileges.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'adminer', 'passive'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
            'https://github.com/vrana/adminer/security/advisories/GHSA-q4f2-39gr-45jh',
            'https://github.com/vrana/adminer/commit/21d3a3150388677b18647d68aec93b7850e457d3',
        ],
        'cve': 'CVE-2026-25892',
    }

    def run(self):
        for path in ('/adminer.php', '/editor.php', '/adminer/'):
            r = self.http_request(method='GET', path=path, allow_redirects=True, headers={'Accept-Language': 'en-US,en;q=0.5'})
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('Adminer</title>', 'Adminer</a>',)
            if any(m in body for m in body_any):
                self.set_info(
                    severity='high',
                    reason='Adminer 4.6.2 - 5.4.1 Unauthenticated Persistent DoS detected',
                    path=path,
                )
                return True
        return False

