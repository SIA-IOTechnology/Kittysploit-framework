#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""User Registration & Membership WordPress plugin <= 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'User Registration & Membership WordPress plugin - Open Redirect Detection',
        'description': "User Registration & Membership WordPress plugin <= 5.1.4 contains an open redirect caused by insufficient validation of 'redirect_to_on_logout' parameter, letting attackers redirect users to malicious external URLs after logout, exploit requires crafted URL.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'wp', 'wordpress', 'wp-plugin', 'user-registration', 'open-redirect'],
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
            'https://patchstack.com/database/vulnerability/wordpress-user-registration-membership-plugin-5-1-4-unauthenticated-open-redirect-via-redirect-to-on-logout-parameter-vulnerability',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-6203',
        ],
        'cve': 'CVE-2026-6203',
    }

    def run(self):
        path = '/wp-content/plugins/user-registration/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('User Registration',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/?user-logout=true&redirect_to_on_logout=https://interact.sh'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 302:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('Location: https://interact.sh',)
        if any(m in headers for m in header_any):
            self.set_info(severity='medium', reason='User Registration & Membership WordPress plugin - Open Redirect detected', path=path)
            return True
        return False

