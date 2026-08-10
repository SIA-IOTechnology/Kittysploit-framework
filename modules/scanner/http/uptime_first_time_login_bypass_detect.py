#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects up."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'up.time - firstTimeLogin Authentication Bypass Detection',
        'description': (
            'Detects up.time <= 5.0 auth bypass surface via index.php?userid=admin&firstTimeLogin=True matching blank-password validation response.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'uptime', 'auth-bypass', 'unauth', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 0.85,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.securityfocus.com/bid/47599',
        ],
    }

    def run(self):
        # Require up.time branding before treating blank-password message as signal.
        home = self.http_request(method='GET', path='/index.php', allow_redirects=False)
        home_body = (home.text or '') if home else ''
        if not any(x in home_body.lower() for x in ('uptime', 'up.time', 'idera')):
            return False
        path = (
            '/index.php?userid=admin&firstTimeLogin=True&password=&confirmPassword='
            '&adminEmail=admin@admin&monitorEmail=admin@admin'
        )
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if r and 'The password cannot be blank' in (r.text or ''):
            self.set_info(
                severity='high',
                reason='up.time firstTimeLogin authentication bypass surface',
                path='/index.php',
            )
            return True
        return False

