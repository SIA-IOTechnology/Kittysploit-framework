#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects the presence of the Label Studio sign-up."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Label Studio - Sign-up Detect',
        'description': 'Detects the presence of the Label Studio sign-up.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'label-studio', 'sign-up', 'misconfig', 'vuln'],
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
    }

    def run(self):
        path = '/user/signup'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Accept': '*/*'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Label Studio', 'Sign up', 'Create Account',)
        if all(m in body for m in body_all):
            self.set_info(severity='info', reason='Label Studio - Sign-up detected', path=path)
            return True
        return False

