#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""This template checks for the default credentials (username: 11111, password: x-admin) on Fuji Xerox ApeosPort ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Fuji Xerox ApeosPort - Default Login Detection',
        'description': 'This template checks for the default credentials (username: 11111, password: x-admin) on Fuji Xerox ApeosPort series printers. If the credentials are valid, the response will have a 200 HTTP status code. Tested on a Fuji Xerox ApeosPort-V C2275 T2.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'default-login', 'fuji', 'fuji-xerox', 'printer', 'vuln'],
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
        'references': ['https://4it.com.au/kb/article/fuji-xerox-default-password/'],
    }

    def run(self):
        path = '/prop.htm'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Authorization': 'Basic MTExMTE6eC1hZG1pbg==', 'Connection': 'close'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Configuration Overview', 'Description', 'System Administrator Settings',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Fuji Xerox ApeosPort - Default Login detected', path=path)
            return True
        return False

