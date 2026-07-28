#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Issues with information disclosure in redirect responses."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'FleetCart 4.1.1 - Information Disclosure Detection',
        'description': 'Issues with information disclosure in redirect responses. Accessing the majority of the website\'s pages exposes sensitive data, including the "Razorpay" "razorpayKeyId".',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'packetstorm', 'cms', 'fleetcart', 'info-leak', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2024-5230',
            'https://packetstormsecurity.com/files/178770/FleetCart-4.1.1-Information-Disclosure.html',
            'https://codecanyon.net/item/fleetcart-laravel-ecommerce-system/23014826',
            'https://vuldb.com/?ctiid.265981',
            'https://vuldb.com/?id.265981',
        ],
        'cve': 'CVE-2024-5230',
    }

    def run(self):
        r = self.http_request(method="GET", path='/en/products?query=123', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ("razorpayKeyId: ''",)
        body_all = ('razorpayKeyId:', 'loggedIn:', 'storeName:',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="FleetCart 4.1.1 - Information Disclosure detected",
                path='/en/products?query=123',
            )
            return True
        return False

