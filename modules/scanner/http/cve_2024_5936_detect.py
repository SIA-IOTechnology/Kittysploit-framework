#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An open redirect vulnerability exists in imartinez/privategpt version 0."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PrivateGPT < 0.5.0 - Open Redirect Detection',
        'description': "An open redirect vulnerability exists in imartinez/privategpt version 0.5.0 due to improper handling of the 'file' parameter. This vulnerability allows attackers to redirect users to a URL specified by user-controlled input without proper validation or sanitization.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'private-gpt', 'redirect', 'vuln', 'ai'],
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
            'https://huntr.com/bounties/43f05c1e-d7b8-45e2-b1fe-48faf1e3a48d',
            'https://drive.google.com/file/d/1Fw5eT-9bAqsqzNUqdTXebtqIo5NI6T48/view',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-5936',
        ],
        'cve': 'CVE-2024-5936',
    }

    def run(self):
        r = self.http_request(method="GET", path='/file=https://oast.me', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_\\.@]*)oast\\.me.*$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="PrivateGPT < 0.5.0 - Open Redirect detected",
                path='/file=https://oast.me',
            )
            return True
        return False

