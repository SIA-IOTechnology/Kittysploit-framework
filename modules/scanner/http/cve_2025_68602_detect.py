#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Accept Donations with PayPal & Stripe plugin for WordPress is vulnerable to Open Redirect in all versions ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Accept Donations with PayPal <= 1.5.2 - Open Redirect Detection',
        'description': 'The Accept Donations with PayPal & Stripe plugin for WordPress is vulnerable to Open Redirect in all versions up to, and including, 1.5.2. This is due to insufficient validation on the redirect url supplied. This makes it possible for unauthenticated attackers to redirect users to potentially malicious sites if they can successfully trick them into performing an action.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'wordpress', 'wp', 'wp-plugin', 'redirect', 'easy-paypal-donation', 'unauth'],
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
            'https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/easy-paypal-donation/accept-donations-with-paypal-152-unauthenticated-open-redirect',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-68602',
        ],
        'cve': 'CVE-2025-68602',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?wpedon-stripe-checkout-redirect=1&sk=nucleitest&ai=nucleitest&si=nucleitest&rf=//oast.pro', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('src="https://js.stripe.com/v3/"', "let rf = '//oast.pro", 'window.location.href = rf;',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Accept Donations with PayPal <= 1.5.2 - Open Redirect detected",
                path='/?wpedon-stripe-checkout-redirect=1&sk=nucleitest&ai=nucleitest&si=nucleitest&rf=//oast.pro',
            )
            return True
        return False

