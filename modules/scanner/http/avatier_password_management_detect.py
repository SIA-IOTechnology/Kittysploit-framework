#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An Avatier password management panel was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Avatier Password Management Panel Detection',
        'description': 'An Avatier password management panel was detected.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'edb', 'avatier', 'aims'],
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
                'confidence_min': {
                },
                'confidence_min_any': {
                },
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
                'option_bindings': {
                },
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://www.exploit-db.com/ghdb/6576',
            'https://www.avatier.com/products/identity-management/password-management/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/aims/ps/', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "")
        markers = (
            'LabelWelcomeToPS',
            'Avatier Corporation',
            'Welcome to Password Management',
            'Password Management Client',
        )
        if any(m in body for m in markers):
            self.set_info(
                severity='info',
                reason="Avatier Password Management Panel detected",
                path='/aims/ps/',
            )
            return True
        return False

