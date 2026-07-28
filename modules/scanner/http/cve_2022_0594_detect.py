#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Shareaholic plugin prior to 9."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Shareaholic <9.7.6 - Information Disclosure Detection',
        'description': 'WordPress Shareaholic plugin prior to 9.7.6 is susceptible to information disclosure. The plugin does not have proper authorization check in one of the AJAX actions, available to both unauthenticated (before 9.7.5) and authenticated (in 9.7.5) users, allowing them to possibly obtain sensitive information such as active plugins and different versions (PHP, cURL, WP, etc.).',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wordpress', 'wp', 'wp-plugin', 'exposure', 'wpscan', 'shareaholic', 'vuln'],
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
            'https://wpscan.com/vulnerability/4de9451e-2c8d-4d99-a255-b027466d29b1',
            'https://wordpress.org/plugins/shareaholic/',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0594',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-0594',
            'https://github.com/20142995/sectool',
        ],
        'cve': 'CVE-2022-0594',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin-ajax.php?action=shareaholic_debug_info', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('plugin_version', 'shareaholic_server_reachable',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WordPress Shareaholic <9.7.6 - Information Disclosure detected",
                path='/wp-admin/admin-ajax.php?action=shareaholic_debug_info',
            )
            return True
        return False

