#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Pie Register < 3."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Pie Register < 3.7.2.4 - Open Redirect Detection',
        'description': 'WordPress Pie Register < 3.7.2.4 is susceptible to an open redirect vulnerability because the plugin passes unvalidated user input to the wp_redirect() function.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'vulnerability', 'redirect', 'wp-plugin', 'pieregister', 'wpscan', 'wordpress', 'vuln'],
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
            'https://wpscan.com/vulnerability/f6efa32f-51df-44b4-bbba-e67ed5785dd4',
            'https://wordpress.org/plugins/pie-register/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/?piereg_logout_url=true&redirect_to=https://interact.sh', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh.*$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='low',
                reason="WordPress Pie Register < 3.7.2.4 - Open Redirect detected",
                path='/?piereg_logout_url=true&redirect_to=https://interact.sh',
            )
            return True
        return False

