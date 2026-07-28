#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pega Infinity versions 8."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Pega Infinity - Authentication Bypass Detection',
        'description': 'Pega Infinity versions 8.2.1 through 8.5.2 contain an authentication bypass vulnerability because the password reset functionality for local accounts can be used to bypass local authentication checks.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'pega', 'auth-bypass', 'passive', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/samwcyo/CVE-2021-27651-PoC/blob/main/RCE.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-27651',
            'https://collaborate.pega.com/discussion/pega-security-advisory-a21-hotfix-matrix',
            'https://github.com/nomi-sec/PoC-in-GitHub',
            'https://github.com/orangmuda/CVE-2021-27651',
        ],
        'cve': 'CVE-2021-27651',
    }

    def run(self):
        path = '/prweb/PRAuth/app/default/'
        r = self.http_request(method='GET', path=path, allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Pega Infinity',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='critical',
                reason='Pega Infinity - Authentication Bypass detected',
                path=path,
            )
            return True
        return False

