#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Campaign Monitor for WordPress plugin for WordPress versions up to 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Campaign Monitor for WordPress - Information Disclosure Detection',
        'description': 'Campaign Monitor for WordPress plugin for WordPress versions up to 2.8.15 contains a full path disclosure caused by improper access restriction and enabled display_errors in /forms/views/admin/create.php, letting unauthenticated attackers retrieve server paths, exploit requires display_errors to be enabled.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'wordpress', 'wp-plugin', 'fpd', 'campaigns', 'misconfig'],
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
            'https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/forms-for-campaign-monitor/campaign-monitor-for-wordpress-2815-unauthenticated-full-path-disclosure',
            'https://wordpress.org/plugins/forms-for-campaign-monitor/',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-6569',
        ],
        'cve': 'CVE-2024-6569',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/forms-for-campaign-monitor/forms/views/admin/create.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('forms-for-campaign-monitor',)
        body_all = ('Fatal error', 'Uncaught Error', 'Stack trace',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Campaign Monitor for WordPress - Information Disclosure detected",
                path='/wp-content/plugins/forms-for-campaign-monitor/forms/views/admin/create.php',
            )
            return True
        return False

