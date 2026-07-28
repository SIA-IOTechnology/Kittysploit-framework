#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The WP Content Copy Protection & No Right Click plugin before version 15."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WP Content Copy Protection & No Right Click - Open Redirect Detection',
        'description': 'The WP Content Copy Protection & No Right Click plugin before version 15.3 contains an open-redirect vulnerability via the referrer parameter in no-js.php, allowing redirection of users to external sites.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'wordpress', 'wp-plugin', 'redirect', 'wccp-pro', 'unauth', 'vkev'],
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
            'https://wpscan.com/vulnerability/09c6848d-30dc-4382-ae74-b470f586e142/',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-6690',
        ],
        'cve': 'CVE-2024-6690',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/wccp-pro/no-js.php?referrer=https://oast.pro', allow_redirects=False)
        if not r or r.status_code != 302:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)(?:[a-zA-Z0-9\\-_\\.@]*)oast\\.pro.*$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="WP Content Copy Protection & No Right Click - Open Redirect detected",
                path='/wp-content/plugins/wccp-pro/no-js.php?referrer=https://oast.pro',
            )
            return True
        return False

