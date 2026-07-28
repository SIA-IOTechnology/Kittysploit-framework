#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""N-central server versions prior to 2024."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'N-able N-central < 2024.2 - Authentication Bypass Detection',
        'description': 'N-central server versions prior to 2024.2 contain an authentication bypass in the user interface, letting attackers access restricted areas without proper credentials, exploit requires no specific conditions.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'n-able', 'ncentral', 'passive', 'vuln', 'vkev'],
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
            'https://status.n-able.com/2024/07/02/n-central-critical-security-fix-details/',
            'https://me.n-able.com/s/security-advisory/aArVy0000000673KAA/cve202428200-ncentral-authentication-bypass',
            'https://www.incibe.es/incibe-cert/alerta-temprana/vulnerabilidades/cve-2024-28200',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-28200',
        ],
        'cve': 'CVE-2024-28200',
    }

    def run(self):
        path = '/login'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('class="ncentral"',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='critical',
                reason='N-able N-central < 2024.2 - Authentication Bypass detected',
                path=path,
            )
            return True
        return False

