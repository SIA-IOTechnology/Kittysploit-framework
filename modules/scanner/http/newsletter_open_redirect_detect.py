#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Newsletter Manager < 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Newsletter Manager < 1.5 - Unauthenticated Open Redirect Detection',
        'description': 'WordPress Newsletter Manager < 1.5 is susceptible to an open redirect vulnerability. The plugin used base64 encoded user input in the appurl parameter without validation to redirect users using the header() PHP function, leading to an open redirect issue.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'redirect', 'wp-plugin', 'newsletter', 'wp', 'wpscan', 'wordpress', 'vuln'],
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
        'references': ['https://wpscan.com/vulnerability/847b3878-da9e-47d6-bc65-3cfd2b3dc1c1'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/?wp_nlm=confirmation&appurl=aHR0cDovL2ludGVyYWN0LnNo', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh\\/?(\\/|[^.].*)?$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="WordPress Newsletter Manager < 1.5 - Unauthenticated Open Redirect detected",
                path='/?wp_nlm=confirmation&appurl=aHR0cDovL2ludGVyYWN0LnNo',
            )
            return True
        return False

