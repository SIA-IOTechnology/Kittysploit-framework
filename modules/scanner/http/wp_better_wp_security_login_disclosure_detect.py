#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Solid Security (formerly iThemes Security/Better WP Security) plugin before 9."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Solid Security < 9.0.1 - Unauthenticated Login Page Disclosure Detection',
        'description': 'WordPress Solid Security (formerly iThemes Security/Better WP Security) plugin before 9.0.1 is vulnerable to login page disclosure. When the Hide Backend feature is enabled and comments require user registration, the secret login URL token is exposed in the HTML source via the itsec-hb-token parameter in the comment form login links.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'wordpress', 'wp-plugin', 'wp', 'exposure', 'ithemes', 'solid-security'],
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://wordpress.org/plugins/better-wp-security/',
            'https://wpscan.com/vulnerability/b7201fc1-d825-484f-aca9-ba14a968179b/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('itsec-hb-token=',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="WordPress Solid Security < 9.0.1 - Unauthenticated Login Page Disclosure detected",
                path='/',
            )
            return True
        return False

