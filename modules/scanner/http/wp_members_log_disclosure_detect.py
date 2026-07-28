#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The WordPress Members plugin exposes error/debug log files that may contain sensitive information."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Members Plugin - Debug/Error Log Disclosure Detection',
        'description': 'The WordPress Members plugin exposes error/debug log files that may contain sensitive information.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'wordpress', 'wp-plugin', 'members', 'exposure', 'logs'],
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
            'https://wordpress.org/plugins/members/',
            'https://pentest-tools.com/vulnerabilities-exploits/wordpress-members-membership-and-user-role-editor-plugin-error-log-disclosure_28354',
        ],
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('/members',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/wp-content/debug.log'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('PHP Warning:', 'PHP Notice:', 'Undefined array', 'Undefined variable',)
        body_regexes = ('[[0-9]{2}-[a-zA-Z]{3}-[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} [A-Z]{3}] PHP',)
        if (any(m in body for m in body_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='low', reason='WordPress Members Plugin - Debug/Error Log Disclosure detected', path=path)
            return True
        return False

