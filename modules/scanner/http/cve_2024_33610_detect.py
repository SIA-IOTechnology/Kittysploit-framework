#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""It was observed that Sharp printers are vulnerable to a listing of session cookies without authentication."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Sharp Multifunction Printers - Cookie Exposure Detection',
        'description': 'It was observed that Sharp printers are vulnerable to a listing of session cookies without authentication. Any attacker can list valid cookies by visiting a backdoor webpage and use them to authenticate to the printers.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'sharp', 'printer', 'exposure', 'vuln'],
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
            'https://pierrekim.github.io/blog/2024-06-27-sharp-mfp-17-vulnerabilities.html#pre-auth-cookies',
            'https://jvn.jp/en/vu/JVNVU93051062/index.html',
            'https://global.sharp/products/copier/info/info_security_2024-05.html',
        ],
        'cve': 'CVE-2024-33610',
    }

    def run(self):
        r = self.http_request(method="GET", path='/sessionlist.html', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('No.', 'User', 'From', 'Last login', 'Last access', 'Language ID', 'Cookie',)
        header_any = ('Set-Cookie: MFPSESSIONID=',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Sharp Multifunction Printers - Cookie Exposure detected",
                path='/sessionlist.html',
            )
            return True
        return False

