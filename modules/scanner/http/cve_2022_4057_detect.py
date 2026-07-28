#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Autoptimize WordPress plugin before 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Autoptimize < 3.1.0 - Information Disclosure Detection',
        'description': "The Autoptimize WordPress plugin before 3.1.0 uses an easily guessable path to store plugin's exported settings and logs.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wpscan', 'wp', 'wordpress', 'wp-plugin', 'disclosure', 'autoptimize', 'optimizingmatters', 'vuln'],
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
            'https://wpscan.com/vulnerability/95ee1b9c-1971-4c35-8527-5764e9ed64af',
            'https://wordpress.org/plugins/autoptimize/',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-4057',
        ],
        'cve': 'CVE-2022-4057',
    }

    def run(self):
        for path in ('/wp-content/uploads/ao_ccss/queuelog.html', '/blog/wp-content/uploads/ao_ccss/queuelog.html'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('Job id &lt;', 'log messages',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='medium',
                    reason="Autoptimize < 3.1.0 - Information Disclosure detected",
                    path=path,
                )
                return True
        return False

