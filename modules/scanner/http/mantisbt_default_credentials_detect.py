#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MantisBT default credentials (administrator/root)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MantisBT - Default Credentials Detection',
        'description': (
            'Tries the known MantisBT default credentials administrator:root against '
            '/login.php and looks for MANTIS_STRING_COOKIE / login_cookie_test redirect.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'mantisbt', 'default-credentials', 'auth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
        'references': ['https://www.mantisbt.org/'],
    }

    base_path = OptString('', 'Optional MantisBT base path prefix', required=False)

    def _prefix(self) -> str:
        base = str(self.base_path or '').strip()
        if not base or base == '/':
            return ''
        if not base.startswith('/'):
            base = '/' + base
        return base.rstrip('/')

    def run(self):
        path = f'{self._prefix()}/login.php'
        r = self.http_request(
            method='POST',
            path=path,
            data='return=index.php&username=administrator&password=root',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            allow_redirects=False,
        )
        if not r or r.status_code not in (302, 301):
            return False
        headers = '\n'.join(f'{k}: {v}' for k, v in r.headers.items())
        loc = r.headers.get('Location') or r.headers.get('location') or ''
        if (
            'MANTIS_STRING_COOKIE=' in headers
            or 'login_cookie_test.php?return=' in loc
        ):
            self.set_info(
                severity='high',
                reason='MantisBT default credentials administrator:root accepted',
                path=path,
            )
            return True
        return False
