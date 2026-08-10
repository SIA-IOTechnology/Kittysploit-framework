#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Monit default credentials (admin:monit)."""

import base64

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Monit - Default Credentials Detection',
        'description': (
            'Tries admin:monit against Monit Basic auth (WWW-Authenticate realm=monit) '
            'and looks for <title>Monit: in a 200 response.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'monit', 'default-credentials', 'auth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 0.9,
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
        'references': ['https://mmonit.com/monit/documentation/monit.html'],
    }

    def run(self):
        r = self.http_request(method='GET', path='/', allow_redirects=False)
        if not r or r.status_code != 401:
            return False
        www = r.headers.get('WWW-Authenticate') or r.headers.get('www-authenticate') or ''
        if 'realm="monit"' not in www and "realm='monit'" not in www:
            return False
        token = base64.b64encode(b'admin:monit').decode('ascii')
        r2 = self.http_request(
            method='GET',
            path='/',
            headers={'Authorization': f'Basic {token}'},
            allow_redirects=False,
        )
        if r2 and r2.status_code == 200 and '<title>Monit: ' in (r2.text or ''):
            self.set_info(
                severity='high',
                reason='Monit default credentials admin:monit accepted',
                path='/',
            )
            return True
        return False
