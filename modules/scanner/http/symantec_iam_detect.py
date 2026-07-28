#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Management Console to administrate Symantec Identity Manager environment, authentication is sometimes disabled."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Symantec Identity Manager Management Console Detection',
        'description': 'Management Console to administrate Symantec Identity Manager environment, authentication is sometimes disabled.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'symantec', 'login', 'broadcom'],
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
            'https://techdocs.broadcom.com/us/en/symantec-security-software/identity-security/identity-manager/14-4/configuring/environments-overview/management-console.html',
        ],
    }

    def run(self):
        path = '/iam/immanage/login.jsp'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<title>Management Console</title>',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='info',
                reason='Symantec Identity Manager Management Console detected',
                path=path,
            )
            return True
        return False

