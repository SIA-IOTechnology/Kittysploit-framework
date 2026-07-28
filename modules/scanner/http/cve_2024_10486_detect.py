#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Google for WooCommerce plugin for WordPress is vulnerable to Information Disclosure in all versions up to,."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Google for WooCommerce <= 2.8.6 - Information Disclosure via Publicly Accessible PHP Info File Detection',
        'description': 'The Google for WooCommerce plugin for WordPress is vulnerable to Information Disclosure in all versions up to, and including, 2.8.6. This is due to publicly accessible print_php_information.php file. This makes it possible for unauthenticated attackers to retrieve information about Webserver and PHP configuration, which can be used to aid other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'wp', 'wordpress', 'wp-plugin', 'google-listings-and-ads', 'info-leak', 'vuln'],
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
            'https://plugins.trac.wordpress.org/browser/google-listings-and-ads/tags/2.8.6/vendor/googleads/google-ads-php/scripts/print_php_information.php',
            'https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/google-listings-and-ads/google-for-woocommerce-286-information-disclosure-via-publicly-accessible-php-info-file',
        ],
        'cve': 'CVE-2024-10486',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/google-listings-and-ads/vendor/googleads/google-ads-php/scripts/print_php_information.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('PHP Extension', 'PHP Version',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Google for WooCommerce <= 2.8.6 - Information Disclosure via Publicly Accessible PHP Info File detected",
                path='/wp-content/plugins/google-listings-and-ads/vendor/googleads/google-ads-php/scripts/print_php_information.php',
            )
            return True
        return False

