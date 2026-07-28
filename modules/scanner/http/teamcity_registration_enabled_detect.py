#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JetBrains TeamCity allows all visitors to register due to a misconfiguration."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'JetBrains TeamCity - Registration Enabled Detection',
        'description': 'JetBrains TeamCity allows all visitors to register due to a misconfiguration.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfig', 'auth-bypass', 'teamcity', 'jetbrains', 'intrusive', 'vuln'],
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
            'https://ph33r.medium.com/misconfig-in-teamcity-panel-lead-to-auth-bypass-in-apache-org-0day-146f6a1a4e2b',
        ],
    }

    def run(self):
        path = '/registerUser.html?init=1'
        r = self.http_request(method='GET', path=path, allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<title>Register a New User Account ? TeamCity</title>',)
        if any(m in body for m in body_any):
            self.set_info(severity='high', reason='JetBrains TeamCity - Registration Enabled detected', path=path)
            return True
        return False

