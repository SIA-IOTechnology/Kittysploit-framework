#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Graphql Tartiflette Detect."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Graphql Tartiflette Detect',
        'description': 'Detects Graphql Tartiflette Detect.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'technology', 'tech', 'graphql', 'tartiflette'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
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
        'references': ['https://github.com/dolevf/graphw00f/blob/main/graphw00f/lib.py'],
    }

    def run(self):
        for path in ('/graphql', '/api/graphql', '/query', '/'):
            r = self.http_request(method='POST', path=path, allow_redirects=True, headers={'Content-Type': 'application/json'}, data='{"query":"query @a { __typename }"}')
            if not r or r.status_code not in (200, 400):
                continue
            body = r.text or ""
            body_any = ('Unknow Directive < @a >.',)
            if any(m in body for m in body_any):
                self.set_info(
                    severity='info',
                    reason='Graphql Tartiflette detected',
                    path=path,
                )
                return True
        return False

