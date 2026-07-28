#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Embedthis HTTP library, and Appweb versions before 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AppWeb - Authentication Bypass Detection',
        'description': 'The Embedthis HTTP library, and Appweb versions before 7.0.3, have a logic flaw related to the authCondition function in http/httpLib.c. With a forged HTTP request, it is possible to bypass authentication for the form and digest login types.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'appweb', 'auth-bypass', 'embedthis', 'vuln'],
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
            'https://github.com/embedthis/appweb/issues/610',
            'https://blogs.securiteam.com/index.php/archives/3676',
            'https://security.paloaltonetworks.com/CVE-2018-8715',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-8715',
            'https://github.com/cyberharsh/appweb',
        ],
        'cve': 'CVE-2018-8715',
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<a class="logo" href="https://embedthis.com/">&nbsp;</a>',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="AppWeb - Authentication Bypass detected",
                path='/',
            )
            return True
        return False

