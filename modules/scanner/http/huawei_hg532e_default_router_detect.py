#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Huawei HG532e default admin credentials were discovered."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Huawei HG532e Default Credential Detection',
        'description': 'Huawei HG532e default admin credentials were discovered.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'default-login', 'huawei', 'vuln'],
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
        path = '/index/login.cgi'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Cookie': 'Language=en; FirstMenu=Admin_0; SecondMenu=Admin_0_0; ThirdMenu=Admin_0_0_0', 'Content-Type': 'application/x-www-form-urlencoded'}, data='Username=user&Password=MDRmODk5NmRhNzYzYjdhOTY5YjEwMjhlZTMwMDc1NjllYWYzYTYzNTQ4NmRkYWIyMTFkNTEyYzg1YjlkZjhmYg%3D%3D\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<title>replace</title>',)
        header_any = ('Set-Cookie: SessionID',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='high', reason='Huawei HG532e Default Credential detected', path=path)
            return True
        return False

