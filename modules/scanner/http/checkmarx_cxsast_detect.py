#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Checkmarx CxSAST login panel was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Checkmarx CxSAST Login Panel - Detect',
        'description': 'Checkmarx CxSAST login panel was detected.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'checkmarx', 'cxsast', 'login'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
        'references': ['https://docs.checkmarx.com/en/34965-44074-checkmarx-sast.html'],
    }

    def run(self):
        for path in ('/cxrestapi/help/system/version', '/cxwebclient/Login.aspx', '/cxrestapi/auth/identity/.well-known/openid-configuration'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "").lower()
            body_any = ('cxsastmanageruri', 'cxauthorityconfigurations', '/cxwebclient/webapp/', 'sast_api', 'sast_rest_api', 'sast-permissions', 'hotfix',)
            if any(m in body for m in body_any):
                self.set_info(
                    severity='info',
                    reason='Checkmarx CxSAST Login Panel detected',
                    path=path,
                )
                return True
        return False

