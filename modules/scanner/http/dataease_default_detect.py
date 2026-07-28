#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dataease has a built-in account demo/dataease, and many developers forget to delete or change the account pass."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Dataease - Default Login Detection',
        'description': 'Dataease has a built-in account demo/dataease, and many developers forget to delete or change the account password. As a result, many Dataease can log in with this built-in account.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'default-login', 'dataease', 'vuln'],
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
        'references': ['https://github.com/dataease/dataease/issues/5995'],
    }

    def run(self):
        path = '/api/auth/login'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{\n  "username": "HmFJtDmMa9MZjlWEpCNAo7Yh/hRBI7mrCRfFTok7wES7qcpIJ04x0OQXW5fwtL4WtN29408wyAupmtMjvvXjag==",\n  "password": "sL+oQsnErJMYGiLyzXj/Hy2opaZcSnfjGtYtm48q8tdkkINxzTtAOFI2NgDoorchFE790vWQYIgo1CMyjJ2jnw==",\n  "loginType": 0\n}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"success":true', '"token":',)
        if all(m in body for m in body_all):
            self.set_info(
                severity='high',
                reason='Dataease - Default Login detected',
                path=path,
            )
            return True
        return False

