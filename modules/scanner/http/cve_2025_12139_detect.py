#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""File Manager for Google Drive - Integrate Google Drive with WordPress plugin for WordPress <= 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Integrate Google Drive <= 1.5.3 - Information Disclosure Detection',
        'description': 'File Manager for Google Drive - Integrate Google Drive with WordPress plugin for WordPress <= 1.5.3 contains sensitive information exposure caused by improper protection of the get_localize_data function, letting unauthenticated attackers extract Google OAuth credentials and account email addresses, exploit requires no authentication.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'wordpress', 'wp-plugin', 'exposure', 'token', 'google-drive'],
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
            'https://wordpress.org/plugins/integrate-google-drive/',
            'https://github.com/Galaxy-sc/CVE-2025-12139-WordPress-Integrate-Google-Drive-Exploit',
        ],
        'cve': 'CVE-2025-12139',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('var igd',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='high',
                reason='Integrate Google Drive <= 1.5.3 - Information Disclosure detected',
                path=path,
            )
            return True
        return False

