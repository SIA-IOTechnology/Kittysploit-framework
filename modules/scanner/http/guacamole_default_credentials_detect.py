#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Guacamole default credentials (guacadmin/guacadmin)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Guacamole - Default Credentials Detection',
        'description': (
            'Tries guacadmin:guacadmin against /api/tokens and looks for authToken in a '
            'JSON 200 response.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'guacamole', 'apache', 'default-credentials', 'auth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
        'references': [
            'https://guacamole.apache.org/doc/gug/administration.html',
        ],
    }

    base_path = OptString('', 'Optional Guacamole base path', required=False)

    def _prefix(self) -> str:
        base = str(self.base_path or '').strip()
        if not base or base == '/':
            return ''
        if not base.startswith('/'):
            base = '/' + base
        return base.rstrip('/')

    def run(self):
        path = f'{self._prefix()}/api/tokens'
        r = self.http_request(
            method='POST',
            path=path,
            data='username=guacadmin&password=guacadmin',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return False
        body = r.text or ''
        ctype = (r.headers.get('Content-Type') or '').lower()
        if 'application/json' not in ctype:
            return False
        if re.search(r'"authToken"\s*:\s*"[^"]+"', body) and '"username":"guacadmin"' in body.replace(' ', ''):
            self.set_info(
                severity='high',
                reason='Apache Guacamole default credentials guacadmin:guacadmin accepted',
                path=path,
            )
            return True
        # Looser match if spacing differs
        if re.search(r'"authToken"\s*:\s*"[^"]+"', body) and re.search(
            r'"username"\s*:\s*"guacadmin"', body
        ):
            self.set_info(
                severity='high',
                reason='Apache Guacamole default credentials guacadmin:guacadmin accepted',
                path=path,
            )
            return True
        return False
