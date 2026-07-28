#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The plugin redirects to any URL via the "wptbto" parameter."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Toolbar <= 2.2.6 - Open Redirect Detection',
        'description': 'The plugin redirects to any URL via the "wptbto" parameter. This makes it possible for unauthenticated attackers to redirect users to potentially malicious sites if they can successfully trick them into performing an action.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'wpscan', 'cve2023', 'wordpress', 'wp-plugin', 'wordpress-toolbar', 'wp', 'redirect', 'abhinavsingh', 'vuln'],
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
            'https://wpscan.com/vulnerability/04dafc55-3a8d-4dd2-96da-7a8b100e5a81/',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-6389',
        ],
        'cve': 'CVE-2023-6389',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/wordpress-toolbar/toolbar.php?wptbto=https://oast.me&wptbhash=acme', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_\\.@]*)oast\\.me.*$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="WordPress Toolbar <= 2.2.6 - Open Redirect detected",
                path='/wp-content/plugins/wordpress-toolbar/toolbar.php?wptbto=https://oast.me&wptbhash=acme',
            )
            return True
        return False

