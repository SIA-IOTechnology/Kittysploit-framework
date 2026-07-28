#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Thumbs DB Disclosure."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Thumbs DB Disclosure Detection',
        'description': 'Detects Thumbs DB Disclosure.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'exposure', 'files', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
        'references': [
            'https://github.com/detectify/ugly-duckling/blob/master/modules/crowdsourced/thumbs-db-disclosure.json',
        ],
    }

    def run(self):
        path = '/Thumbs.db'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        raw = r.content or b""
        binary_hex = ('D0CF11E0A1B11AE1',)
        if any(bytes.fromhex(h) in raw for h in binary_hex):
            self.set_info(
                severity='info',
                reason='Thumbs DB Disclosure detected',
                path=path,
            )
            return True
        return False

