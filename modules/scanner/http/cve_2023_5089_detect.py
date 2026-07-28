#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Defender Security WordPress plugin before 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Defender Security < 4.1.0 - Protection Bypass (Hidden Login Page) Detection',
        'description': 'The Defender Security WordPress plugin before 4.1.0 does not prevent redirects to the login page via the auth_redirect WordPress function, allowing an unauthenticated visitor to access the login page, even when the hide login page functionality of the plugin is enabled.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'wordpress', 'wpscan', 'wp-plugin', 'defender-security', 'redirect', 'wpmudev', 'vuln'],
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
            'https://www.sprocketsecurity.com/resources/discovering-wp-admin-urls-in-wordpress-with-gravityforms',
            'https://wpscan.com/vulnerability/2b547488-187b-44bc-a57d-f876a7d4c87d/',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5089',
        ],
        'cve': 'CVE-2023-5089',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?gf_page=randomstring', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        body_any = ('wp-login.php',)
        header_any = ('%2f%3fgf_page%3drandomstring&reauth=1',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Defender Security < 4.1.0 - Protection Bypass (Hidden Login Page) detected",
                path='/?gf_page=randomstring',
            )
            return True
        return False

