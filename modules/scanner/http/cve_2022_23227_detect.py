#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NUUO NVRmini 2 unauthenticated handle_import_user.php (CVE-2022-23227)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'NUUO NVRmini 2 - Unauth handle_import_user Detection (CVE-2022-23227)',
        'description': (
            'NUUO NVRmini 2 devices expose /handle_import_user.php without authentication '
            '(CVE-2022-23227 / related CVE-2011-5325 upload surface). Detection matches '
            'the Greenbone active check response fingerprint.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2022', 'nuuo', 'nvr', 'iot', 'unauth',
            'upload', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 0.9,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2022-23227',
            'https://nvd.nist.gov/vuln/detail/CVE-2011-5325',
        ],
        'cve': 'CVE-2022-23227',
    }

    def run(self):
        path = '/handle_import_user.php'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        if 'There was an error uploading the file' in (r.text or ''):
            self.set_info(
                severity='critical',
                reason='NUUO NVRmini 2 unauthenticated handle_import_user.php exposed',
                path=path,
            )
            return True
        return False
