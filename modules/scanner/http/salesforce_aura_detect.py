#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A Salesforce Lightning aura API was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Salesforce Lightning - API Detection',
        'description': 'A Salesforce Lightning aura API was detected.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misconfiguration', 'aura', 'unauth', 'salesforce', 'exposure', 'misconfig', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 5,
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
            'https://www.enumerated.de/index/salesforce',
            'https://github.com/Ph33rr/cirrusgo (test endpoint)',
        ],
    }

    def run(self):
        for path in ('/aura', '/s/sfsites/aura', '/sfsites/aura', '/s/aura', '/s/fact'):
            r = self.http_request(method='POST', path=path, allow_redirects=False, data='{}')
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('aura:invalidSession',)
            if any(m in body for m in body_any):
                self.set_info(
                    severity='info',
                    reason='Salesforce Lightning - API detected',
                    path=path,
                )
                return True
        return False

