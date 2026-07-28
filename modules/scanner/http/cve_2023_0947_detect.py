#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Path Traversal in GitHub repository flatpressblog/flatpress prior to 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Flatpress < 1.3 - Path Traversal Detection',
        'description': 'Path Traversal in GitHub repository flatpressblog/flatpress prior to 1.3.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'huntr', 'lfi', 'flatpress', 'listing', 'vuln'],
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
            'https://huntr.dev/bounties/7379d702-72ff-4a5d-bc68-007290015496/',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-0947',
            'https://github.com/flatpressblog/flatpress/commit/9c4e5d6567e446c472f3adae3b2fe612f66871c7',
        ],
        'cve': 'CVE-2023-0947',
    }

    def run(self):
        for path in ('/fp-content/', '/flatpress/fp-content/'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('<title>Index of /fp-content</title>',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='critical',
                    reason="Flatpress < 1.3 - Path Traversal detected",
                    path=path,
                )
                return True
        return False

