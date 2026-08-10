#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Edimax router HTTP Basic default credentials admin:1234 (CVE-2004-1791)."""

import base64
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Edimax Router - Default Credentials (admin/1234)',
        'description': (
            'Detects Edimax (and similar) routers advertising Basic realm '
            '"Default: admin/1234" and accepts login with those credentials (CVE-2004-1791).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2004', 'edimax', 'router', 'iot',
            'default-login', 'default-credentials', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
            'value': 0.9,
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
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.exploit-db.com/exploits/38056',
            'https://nvd.nist.gov/vuln/detail/CVE-2004-1791',
        ],
        'cve': 'CVE-2004-1791',
    }

    def run(self):
        path = '/'
        r1 = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r1 or r1.status_code != 401:
            return False
        www = r1.headers.get('WWW-Authenticate') or r1.headers.get('www-authenticate') or ''
        if 'Basic realm=' not in www or 'Default: admin/1234' not in www:
            # Some stacks put the realm hint only in body/headers blob
            blob = www + '\n' + (r1.text or '')
            if 'Default: admin/1234' not in blob:
                return False

        token = base64.b64encode(b'admin:1234').decode('ascii')
        r2 = self.http_request(
            method='GET',
            path=path,
            headers={'Authorization': f'Basic {token}'},
            allow_redirects=False,
        )
        if not r2 or r2.status_code not in (200, 301, 302, 303, 307, 308):
            return False

        self.set_info(
            severity='high',
            reason='Edimax router default credentials accepted (admin/1234)',
            path=path,
        )
        return True
