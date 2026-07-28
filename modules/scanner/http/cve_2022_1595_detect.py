#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The HC Custom WP-Admin URL WordPress plugin through 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress HC Custom WP-Admin URL <=1.4 - Admin Login URL Disclosure Detection',
        'description': 'The HC Custom WP-Admin URL WordPress plugin through 1.4 leaks the secret login URL when sending a specific crafted request',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'unauth', 'wpscan', 'wordpress', 'wp-plugin', 'wp', 'hc-custom-wp-admin-url', 'vuln'],
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
            'https://wpscan.com/vulnerability/0218c90c-8f79-4f37-9a6f-60cf2f47d47b',
            'https://wordpress.org/plugins/hc-custom-wp-admin-url/',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-1595',
        ],
        'cve': 'CVE-2022-1595',
    }

    def run(self):
        path = '/wp-login.php'
        r = self.http_request(method='HEAD', path=path, allow_redirects=False, headers={'Cookie': 'valid_login_slug=1'})
        if not r or r.status_code != 302:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?i)Set-Cookie:.*wordpress_logged_in_', '(?i)Location:.*(/wp-admin/|/[^/]+/wp-login\\.php)',)
        if any(re.search(rx, headers) for rx in header_regexes):
            self.set_info(severity='medium', reason='WordPress HC Custom WP-Admin URL <=1.4 - Admin Login URL Disclosure detected', path=path)
            return True
        return False

