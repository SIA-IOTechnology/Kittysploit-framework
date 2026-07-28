#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Pie Register plugin before 3."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Pie Register <3.8.2.3 - Open Redirect Detection',
        'description': 'WordPress Pie Register plugin before 3.8.2.3 contains an open redirect vulnerability. The plugin does not properly validate the redirection URL when logging in and login out. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'redirect', 'pie', 'pie-register', 'wpscan', 'genetechsolutions', 'wordpress', 'vkev', 'vuln'],
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
            'https://wpscan.com/vulnerability/832c6155-a413-4641-849c-b98ba55e8551',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-0552',
        ],
        'cve': 'CVE-2023-0552',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin?piereg_logout_url=true&redirect_to=https://oast.me', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)(?:[a-zA-Z0-9\\-_\\.@]*)oast\\.me.*$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="WordPress Pie Register <3.8.2.3 - Open Redirect detected",
                path='/wp-admin?piereg_logout_url=true&redirect_to=https://oast.me',
            )
            return True
        return False

