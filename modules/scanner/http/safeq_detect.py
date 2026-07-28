#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The YSoft SafeQ panel is umbrella printer management software used by many printer vendors."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'YSoft SafeQ Panel - Detect',
        'description': 'The YSoft SafeQ panel is umbrella printer management software used by many printer vendors. This should not be exposed to the public internet.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'ysoft', 'login', 'safeq'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://www.ysoft.com/safeq',
            'https://1617882505.rsc.cdn77.org/YSoft_SAFEQ_Cloud_documentation.pdf',
        ],
    }

    def run(self):
        for path in ('/', '/login'):
            r = self.http_request(method='GET', path=path, allow_redirects=True)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('YSoft SafeQ', 'Y Soft Corporation, a.s.',)
            if any(m in body for m in body_any):
                self.set_info(
                    severity='info',
                    reason='YSoft SafeQ Panel detected',
                    path=path,
                )
                return True
        return False

