#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multiple vendors conf/securitydbData.xml credential disclosure."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'securitydbData.xml - Credential Disclosure Detection',
        'description': (
            'Detects exposed /conf/securitydbData.xml containing AUTHORIZATION-DATA passwords.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'exposure', 'config', 'info-leak', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.2,
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
                'produces_capabilities': [{'capability': 'credential_leak', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [],
    }

    def run(self):
        path = '/conf/securitydbData.xml'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ''
        if '<AUTHORIZATION-DATA>' in body and '<DATA ownername=' in body and 'password=' in body:
            self.set_info(
                severity='high',
                reason='securitydbData.xml credential disclosure',
                path=path,
            )
            return True
        return False
