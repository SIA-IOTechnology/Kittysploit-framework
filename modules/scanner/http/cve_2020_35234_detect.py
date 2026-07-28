#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The WordPress Easy WP SMTP Plugin has its log folder remotely accessible and its content available for access."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SMTP WP Plugin Directory Listing Detection',
        'description': 'The WordPress Easy WP SMTP Plugin has its log folder remotely accessible and its content available for access.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'wordpress', 'wp-plugin', 'smtp', 'wp-ecommerce', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2020-35234',
            'https://blog.nintechnet.com/wordpress-easy-wp-smtp-plugin-fixed-zero-day-vulnerability/',
            'https://wordpress.org/plugins/easy-wp-smtp/#developers',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2020-35234',
    }

    def run(self):
        for path in ('/wp-content/plugins/easy-wp-smtp/', '/wp-content/plugins/wp-mail-smtp-pro/'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('debug', 'log', 'Index of',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='high',
                    reason="SMTP WP Plugin Directory Listing detected",
                    path=path,
                )
                return True
        return False

