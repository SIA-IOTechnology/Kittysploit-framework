#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CockroachDB exposed the Statements Admin UI page and the HTTP endpoint /_status/statements in ways that let no."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'CockroachDB Information Disclosure Detection',
        'description': 'CockroachDB exposed the Statements Admin UI page and the HTTP endpoint /_status/statements in ways that let non-admin users (and in some builds, unauthenticated callers) see SQL text executed across the cluster.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cockroachdb', 'exposure', 'misconfig'],
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
        'references': ['https://github.com/cockroachdb/cockroach/issues/44348'],
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<title>Cockroach Console',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/_status/statements'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('statements', 'planLat', 'keyData', 'stats',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='CockroachDB Information Disclosure detected', path=path)
            return True
        return False

