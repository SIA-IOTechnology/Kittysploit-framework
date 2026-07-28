#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Identified WAGO Web-Based Management interfaces that were accessible using default credentials (admin:wago)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WAGO Web based Management - Default Login Detection',
        'description': 'Identified WAGO Web-Based Management interfaces that were accessible using default credentials (admin:wago).These interfaces are used to configure and monitor WAGO programmable logic controllers (PLCs) and automation systems. Use of factory-default credentials exposed critical OT infrastructure to unauthorized access.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'wago', 'default-login', 'vuln'],
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
    }

    def run(self):
        path = '/wbm/login.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'X-Requested-With': 'XMLHttpRequest', 'Origin': '{{RootURL}}', 'Referer': '{{RootURL}}/wbm/index.php'}, data='{"username":"admin","password":"wago"}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"username":"admin"', '"isDefaultPW":"1"',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='WAGO Web based Management - Default Login detected', path=path)
            return True
        return False

