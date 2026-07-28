#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pgAdmin 4 versions 8."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'pgAdmin 4 - Authentication Bypass Detection',
        'description': 'pgAdmin 4 versions 8.11 and earlier are vulnerable to a security flaw in OAuth2 authentication. This vulnerability allows an attacker to potentially obtain the client ID and secret, leading to unauthorized access to user data.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'pgadmin', 'exposure', 'auth-bypass', 'vkev', 'vuln'],
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
            'https://github.com/EQSTLab/CVE-2024-9014',
            'https://github.com/pgadmin-org/pgadmin4/issues/7945',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-9014',
        ],
        'cve': 'CVE-2024-9014',
    }

    def run(self):
        path = '/login?next=/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('<title>pgAdmin 4</title>', 'OAUTH2_CLIENT_SECRET',)
        body_regexes = ('OAUTH2_CLIENT_SECRET": null',)
        if (all(m in body for m in body_all)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='critical', reason='pgAdmin 4 - Authentication Bypass detected', path=path)
            return True
        return False

