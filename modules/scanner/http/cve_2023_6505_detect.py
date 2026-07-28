#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Prime Mover plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and in."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Prime Mover < 1.9.3 - Sensitive Data Exposure Detection',
        'description': "Prime Mover plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 1.9.2 via directory listing in the 'prime-mover-export-files/1/' folder. This makes it possible for unauthenticated attackers to extract sensitive data including site and configuration information, directories, files, and password hashes.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'wp', 'wp-plugin', 'wordpress', 'exposure', 'prime-mover', 'listing', 'vuln'],
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
            'https://wpscan.com/vulnerability/eca6f099-6af0-4f42-aade-ab61dd792629',
            'https://research.cleantalk.org/cve-2023-6505-prime-mover-poc-exploit/',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-6505',
        ],
        'cve': 'CVE-2023-6505',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/uploads/prime-mover-export-files/1/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Index of /wp-content/uploads/prime-mover-export-files/1', '.wprime',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="Prime Mover < 1.9.3 - Sensitive Data Exposure detected",
                path='/wp-content/uploads/prime-mover-export-files/1/',
            )
            return True
        return False

