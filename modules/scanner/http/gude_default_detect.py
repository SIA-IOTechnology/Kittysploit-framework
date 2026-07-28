#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GUDE 2301 and 2302 default administrator login credentials (admin:admin) were detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GUDE - Default Login Detection',
        'description': 'GUDE 2301 and 2302 default administrator login credentials (admin:admin) were detected.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'default-login', 'gude'],
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': ['https://media.distrelec.com/Web/Downloads/_m/an/Gude_2302-1_ger_man.pdf'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/ov.html?', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Control Panel',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="GUDE - Default Login detected",
                path='/ov.html?',
            )
            return True
        return False

