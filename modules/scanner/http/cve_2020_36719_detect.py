#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The ListingPro - WordPress Directory & Listing Theme for WordPress is vulnerable to Arbitrary Plugin Installat."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ListingPro < 2.6.1 - Arbitrary Plugin Installation/Activation/Deactivation Detection',
        'description': 'The ListingPro - WordPress Directory & Listing Theme for WordPress is vulnerable to Arbitrary Plugin Installation, Activation and Deactivation in versions before 2.6.1. This is due to a missing capability check on the lp_cc_addons_actions function. This makes it possible for unauthenticated attackers to arbitrarily install, activate and deactivate any plugin.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'wp', 'wp-pluginwordpress', 'listingpro', 'passive', 'vkev', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://blog.nintechnet.com/wordpress-listingpro-theme-fixed-a-critical-vulnerability/',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-36719',
        ],
        'cve': 'CVE-2020-36719',
    }

    def run(self):
        path = '/wp-content/themes/listingpro/style.css'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('ListingPro', 'Version:',)
        if all(m in body for m in body_all):
            self.set_info(
                severity='critical',
                reason='ListingPro < 2.6.1 - Arbitrary Plugin Installation/Activation/Deactivation detected',
                path=path,
            )
            return True
        return False

