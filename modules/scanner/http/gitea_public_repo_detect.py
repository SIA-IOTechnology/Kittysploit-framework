#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected publicly accessible Gitea instances exposing repository listings and user information without authent."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Gitea Public Repository - Exposure Detection',
        'description': 'Detected publicly accessible Gitea instances exposing repository listings and user information without authentication.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'gitea', 'exposure', 'misconfig', 'git'],
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
        'references': ['https://gitea.io/', 'https://docs.gitea.io/en-us/'],
    }

    def run(self):
        return False  # disabled: corrupted matchers
        path = '/explore/repos'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        path = '/api/v1/repos/search?q=&limit=50'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = (':',)
        if all(m in body for m in body_all):
            self.set_info(severity='low', reason='Gitea Public Repository - Exposure detected', path=path)
            return True
        return False

