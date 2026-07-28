#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Featured Image from URL (FIFU) plugin for WordPress is vulnerable to Sensitive Information Exposure in all."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Featured Image from URL (FIFU) <= 5.2.7 - Unauthenticated Information Exposure via Log File Detection',
        'description': 'The Featured Image from URL (FIFU) plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 5.2.7 through publicly exposed log files. This makes it possible for unauthenticated attackers to view potentially sensitive information contained in the exposed log files.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'wordpress', 'wp', 'wp-plugin', 'unauth', 'vuln', 'featured-image-from-url', 'log', 'vkev'],
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
        'cve': 'CVE-2025-9985',
    }

    def run(self):
        for path in ('/wp-content/uploads/fifu-plugin.log', '/wp-content/uploads/fifu-cloud.log'):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('{"fifu-dimensions":', '"Invalid size:',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='medium',
                    reason="Featured Image from URL (FIFU) <= 5.2.7 - Unauthenticated Information Exposure via Log File detected",
                    path=path,
                )
                return True
        return False

