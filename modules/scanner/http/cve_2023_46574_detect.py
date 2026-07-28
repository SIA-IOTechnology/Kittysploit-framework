#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An issue in TOTOLINK A3700R v."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TOTOLINK A3700R - Command Injection Detection',
        'description': 'An issue in TOTOLINK A3700R v.9.1.2u.6165_20211012 allows a remote attacker to execute arbitrary code via the FileName parameter of the UploadFirmwareFile function.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'totolink', 'router', 'iot', 'rce', 'vkev', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2023-46574',
            'https://github.com/OraclePi/repo/blob/main/totolink%20A3700R/1/A3700R%20%20V9.1.2u.6165_20211012%20vuln.md',
            'https://github.com/Marco-zcl/POC',
            'https://github.com/d4n-sec/d4n-sec.github.io',
            'https://github.com/wy876/POC',
        ],
        'cve': 'CVE-2023-46574',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<title>TOTOLINK</title>',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/cgi-bin/cstecgi.cgi'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('uid=([0-9(a-z)]+) gid=([0-9(a-z)]+) groups=([0-9(a-z)]+)',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='TOTOLINK A3700R - Command Injection detected', path=path)
            return True
        return False

