#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Brute Ratel C4 (BRc4) is a legit red-teaming tool designed from the ground up with evasion capabilities in min."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Brute Ratel C4 - Detect',
        'description': 'Brute Ratel C4 (BRc4) is a legit red-teaming tool designed from the ground up with evasion capabilities in mind, but in the wrong hands can cause significant damage. Learn how to protect your organization with our Brute Ratel C4 Spotlight.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'c2', 'bruteratel', 'c4', 'vuln'],
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
        'references': ['https://bruteratel.com/'],
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('404 file not found',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='info',
                reason='Brute Ratel C4 detected',
                path=path,
            )
            return True
        return False

