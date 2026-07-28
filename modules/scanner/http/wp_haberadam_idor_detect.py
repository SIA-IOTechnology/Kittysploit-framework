#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""This template is designed to detect a misconfiguration vulnerability in WordPress themes that use the Haberada."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Themes Haberadam JSON API - IDOR and Path Disclosure Detection',
        'description': 'This template is designed to detect a misconfiguration vulnerability in WordPress themes that use the Haberadam JSON API. This vulnerability can lead to an Insecure Direct Object Reference (IDOR) and path disclosure, potentially exposing sensitive information.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'vulnerability', 'wordpress', 'idor', 'wp-theme', 'disclosure', 'vuln'],
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
        'references': ['https://cxsecurity.com/issue/WLB-2021090078'],
    }

    def run(self):
        for path in ('/wp-content/themes/haberadam/api/mobile-info.php?id=', '/blog/wp-content/themes/haberadam/api/mobile-info.php?id='):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('"status"', '"hava"', '"degree"', '"icon"',)
            header_any = ('text/html',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='low',
                    reason="WordPress Themes Haberadam JSON API - IDOR and Path Disclosure detected",
                    path=path,
                )
                return True
        return False

