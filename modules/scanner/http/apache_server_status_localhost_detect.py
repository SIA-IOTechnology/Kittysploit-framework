#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Server Status page is exposed, which may contain information about pages visited by the users, their IP."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Server Status Disclosure Detection',
        'description': 'Apache Server Status page is exposed, which may contain information about pages visited by the users, their IPs or sensitive information such as session tokens.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'apache', 'debug', 'misconfig', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
    }

    def run(self):
        path = '/server-status'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        path = '/server-status'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Forwarded': '127.0.0.1', 'X-Client-IP': '127.0.0.1', 'X-Forwarded-By': '127.0.0.1', 'X-Forwarded-For': '127.0.0.1', 'X-Forwarded-For-IP': '127.0.0.1', 'X-Forwarded-Host': '127.0.0.1', 'X-Host': '127.0.0.1', 'X-Originating-IP': '127.0.0.1', 'X-Remote-Addr': '127.0.0.1', 'X-Remote-IP': '127.0.0.1', 'X-True-IP': '127.0.0.1'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Apache Server Status', 'Server Version',)
        if all(m in body for m in body_all):
            self.set_info(severity='low', reason='Server Status Disclosure detected', path=path)
            return True
        return False

