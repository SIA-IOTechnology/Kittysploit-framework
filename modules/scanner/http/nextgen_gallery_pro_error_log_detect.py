#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The NextGEN Gallery Pro plugin for WordPress may expose debug/error log files that contain sensitive informati."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress NextGEN Gallery Pro - Error Log Disclosure Detection',
        'description': 'The NextGEN Gallery Pro plugin for WordPress may expose debug/error log files that contain sensitive information including file paths, database queries, and potentially credentials. These log files are accessible without authentication.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'wordpress', 'wp', 'wp-plugin', 'nextgen-gallery-pro', 'log', 'exposure'],
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
            'https://wpscan.com/plugin/nextgen-gallery/',
            'https://www.acunetix.com/vulnerabilities/web/wordpress-plugin-nextgen-gallery-wordpress-gallery-information-disclosure-1-9-11/',
        ],
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('nextgen',)
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
            self.set_info(severity='medium', reason='WordPress NextGEN Gallery Pro - Error Log Disclosure detected', path=path)
            return True
        return False

