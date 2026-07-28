#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AC Smart II contains an authentication bypass caused by a hidden password reset form that can be manipulated t."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AC Smart II - Authentication Bypass Detection',
        'description': 'AC Smart II contains an authentication bypass caused by a hidden password reset form that can be manipulated to change the administrator password without verifying login or permissions, letting attackers change admin passwords without authorization.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'unauth', 'auth-bypass', 'vkev'],
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
            'https://www.notion.so/eldruin/Unauthenticated-Administrator-Password-Reset-AC-Smart-II-v2-1-9-Rev-2251-24d27474cccb80a68e47f907b94abed9',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-10204',
        ],
        'cve': 'CVE-2025-10204',
    }

    def run(self):
        return False  # disabled: corrupted matchers
        path = '/Doc/WebLogin.asp'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ()
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='AC Smart II - Authentication Bypass detected', path=path)
            return True
        return False

