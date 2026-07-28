#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Improper Authorization in GitHub repository modoboa/modoboa prior to 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Modoboa < 2.1.0 - Improper Authorization Detection',
        'description': 'Improper Authorization in GitHub repository modoboa/modoboa prior to 2.1.0.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'modoboa', 'exposure', 'disclosure', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
            'https://huntr.com/bounties/351f9055-2008-4af0-b820-01ff66678bf3',
            'https://github.com/modoboa/modoboa/commit/7bcd3f6eb264d4e3e01071c97c2bac51cdd6fe97',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-2227',
        ],
        'cve': 'CVE-2023-2227',
    }

    def run(self):
        path = '/api/v2/parameters/core/'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'User-Agent': '7h3h4ckv157'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('label":', 'default_password":', 'authentication_type":"local',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='Modoboa < 2.1.0 - Improper Authorization detected', path=path)
            return True
        return False

