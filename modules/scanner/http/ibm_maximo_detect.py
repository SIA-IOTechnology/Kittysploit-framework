#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IBM Maximo login panel was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'IBM Maximo Login Panel - Detect',
        'description': 'IBM Maximo login panel was detected.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'maximo', 'ibm', 'login'],
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
            'https://www.ibm.com/support/pages/what-default-username-and-password-websphere-application-server-community-edition-and-how-add-users-admin-group',
            'https://www.ibm.com/products/maximo',
        ],
    }

    def run(self):
        path = '/maximo/webclient/login/login.jsp?appservauth=true'
        r = self.http_request(method='GET', path=path, allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('maximo-icon.png', 'IBM',)
        if all(m in body for m in body_all):
            self.set_info(
                severity='info',
                reason='IBM Maximo Login Panel detected',
                path=path,
            )
            return True
        return False

