#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LottieFiles LottieFiles <= 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'LottieFiles WordPress Plugin <= 3.0.0 - Missing Authorization Detection',
        'description': 'LottieFiles LottieFiles <= 3.0.0 contains a broken access control vulnerability caused by incorrectly configured access control security levels, letting attackers exploit missing authorization, exploit requires no special privileges.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'wordpress', 'wp-plugin', 'lottiefiles', 'vkev'],
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
            'https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/lottiefiles/lottiefiles-300-missing-authorization',
            'https://patchstack.com/database/Wordpress/Plugin/lottiefiles/vulnerability/wordpress-lottiefiles-plugin-3-0-0-broken-access-control-vulnerability?_s_id=cve',
            'https://plugins.svn.wordpress.org/lottiefiles/',
        ],
        'cve': 'CVE-2025-68043',
    }

    def run(self):
        path = '/wp-json/lottiefiles/v1/settings/'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Accept': 'application/json'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('is_block_logged_in',)
        header_any = ('application/json',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='high', reason='LottieFiles WordPress Plugin <= 3.0.0 - Missing Authorization detected', path=path)
            return True
        return False

