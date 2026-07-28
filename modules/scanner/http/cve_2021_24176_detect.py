#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress JH 404 Logger plugin through 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress JH 404 Logger <=1.1 - Cross-Site Scripting Detection',
        'description': 'WordPress JH 404 Logger plugin through 1.1 contains a cross-site scripting vulnerability. Referer and path of 404 pages are not properly sanitized when they are output in the WordPress dashboard, which can lead to executing arbitrary JavaScript code.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'wordpress', 'wp-plugin', 'xss', 'wpscan', 'jh_404_logger_project', 'vuln'],
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
            'https://wpscan.com/vulnerability/705bcd6e-6817-4f89-be37-901a767b0585',
            'https://wordpress.org/plugins/jh-404-logger/',
            'https://ganofins.com/blog/my-first-cve-2021-24176/',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-24176',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-24176',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/jh-404-logger/readme.txt', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('JH 404 Logger',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="WordPress JH 404 Logger <=1.1 - Cross-Site Scripting detected",
                path='/wp-content/plugins/jh-404-logger/readme.txt',
            )
            return True
        return False

