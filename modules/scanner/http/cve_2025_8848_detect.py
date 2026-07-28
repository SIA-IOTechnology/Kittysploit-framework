#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""danny-avila/librechat 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'LibreChat <= 0.7.9 - HTML Injection via Accept-Language Header Detection',
        'description': 'danny-avila/librechat 0.7.9 contains a stored XSS caused by improper sanitization of the Accept-Language header, letting logged-in users inject arbitrary HTML into the html lang= tag, exploit requires user to be logged in.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'librechat', 'html-injection'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2025-8848',
            'https://huntr.com/bounties/a05ebc1f-882a-4adc-b178-d3cefa4b730e',
            'https://github.com/danny-avila/LibreChat',
        ],
        'cve': 'CVE-2025-8848',
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('<html lang="<h3>{{marker}}</h3>">', 'LibreChat',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="LibreChat <= 0.7.9 - HTML Injection via Accept-Language Header detected",
                path='/',
            )
            return True
        return False

