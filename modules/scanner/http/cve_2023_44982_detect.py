#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Jordy Meow Perfect Images (Manage Image Sizes, Thumbnails, Replace, Retina) versions up to 6."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Perfect Images (WP Retina 2x) < 6.4.6 - Sensitive Information Exposure Detection',
        'description': 'Jordy Meow Perfect Images (Manage Image Sizes, Thumbnails, Replace, Retina) versions up to 6.4.5 contain a vulnerability that exposes sensitive information to unauthorized actors, letting attackers access confidential data, exploit requires no specific conditions.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'wordpress', 'wp-plugin', 'wp-retina-2x'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
        'references': ['https://wpscan.com/vulnerability/aba0c4a1-e253-4b5b-b46d-239567567b16/'],
        'cve': 'CVE-2023-44982',
    }

    def run(self):
        for path in ('/wp-content/plugins/wp-retina-2x/classes/wp-retina-2x.log', '/wp-content/uploads/wp-retina-2x.log', '/wp-content/uploads/wp-retina-2x-logs.txt'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('RETINA', 'PATH', 'thumbnail', 'wp-content', 'Full-Size', 'uploads',)
            body_regexes = ('\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}:',)
            if (all(m in body for m in body_all)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='medium',
                    reason="WordPress Perfect Images (WP Retina 2x) < 6.4.6 - Sensitive Information Exposure detected",
                    path=path,
                )
                return True
        return False

