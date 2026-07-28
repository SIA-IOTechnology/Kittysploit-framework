#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Gravity Forms plugin for WordPress stores log files that may be accessible without authentication."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Gravity Forms - Log File Disclosure Detection',
        'description': 'The Gravity Forms plugin for WordPress stores log files that may be accessible without authentication. When logging is enabled, debug and error logs are created in the wp-content/uploads/gravity_forms/logs/ directory. These logs can contain sensitive information including form submission data, file paths, database queries, PHP errors, API keys, and user information.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'wordpress', 'wp', 'wp-plugin', 'gravityforms', 'log', 'disclosure', 'exposure', 'misconfig'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
    }

    def run(self):
        for path in ('/wp-content/plugins/gravityforms/debug.log', '/wp-content/plugins/gravityforms/tmp/debug.log'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('PHP Warning:', 'PHP Notice:', 'Undefined array', 'Undefined variable',)
            body_regexes = ('[[0-9]{2}-[a-zA-Z]{3}-[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} [A-Z]{3}] PHP',)
            if (any(m in body for m in body_any)) and (any(re.search(rx, body) for rx in body_regexes)):
                self.set_info(
                    severity='low',
                    reason='WordPress Gravity Forms - Log File Disclosure detected',
                    path=path,
                )
                return True
        return False

