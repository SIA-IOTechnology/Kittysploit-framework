#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected DbGate instances that allowed anonymous access due to insecure default authentication settings, where."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'DbGate Anonymous Access - Detection',
        'description': 'Detected DbGate instances that allowed anonymous access due to insecure default authentication settings, where unauthenticated users could obtain a valid JWT token and access database management APIs.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfig', 'exposure', 'unauth', 'anonymous', 'dbgate'],
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
        'references': ['https://github.com/dbgate/dbgate', 'https://dbgate.io/', 'https://docs.dbgate.io/'],
    }

    def run(self):
        path = '/auth/login'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{"amoid":"none"}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('{"accessToken":"',)
        if any(m in body for m in body_any):
            self.set_info(severity='high', reason='DbGate Anonymous Accession detected', path=path)
            return True
        return False

