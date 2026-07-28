#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress All-in-One Security plugin through 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress All-in-One Security <=4.4.1 - Hidden Login Page Exposure Detection',
        'description': 'WordPress All-in-One Security plugin through 4.4.1 contains an exposure of the actual URL of the "hidden login page" feature.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'wp-plugin', 'exposure', 'wordpress', 'wp', 'wpscan', 'vuln'],
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
            'https://wpscan.com/vulnerability/467673ad-d0ad-46a3-80c7-8ebb3813a4b3/',
            'https://wordpress.org/plugins/all-in-one-wp-security-and-firewall',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/?aiowpsec_do_log_out=1&al_additional_data=1', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Username or Email Address', 'wp_attempt_focus',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="WordPress All-in-One Security <=4.4.1 - Hidden Login Page Exposure detected",
                path='/?aiowpsec_do_log_out=1&al_additional_data=1',
            )
            return True
        return False

